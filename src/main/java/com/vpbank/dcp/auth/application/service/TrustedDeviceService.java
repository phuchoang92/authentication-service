package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.in.DeviceSummary;
import com.vpbank.dcp.auth.application.port.in.ListDevicesUseCase;
import com.vpbank.dcp.auth.application.port.out.TrustedDeviceRepository;
import com.vpbank.dcp.auth.application.port.out.TrustedDeviceRepository.TrustFirstResult;
import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Owns the device rules (ARCHITECTURE §6.1): which installation is trusted, which is primary, and
 * the direct trust of a customer's first device. {@link LoginService} calls it after the password
 * is verified and decides the session from the answer; it never touches device rows itself.
 */
@RequiredArgsConstructor
public final class TrustedDeviceService implements ListDevicesUseCase {
    @NonNull private final TrustedDeviceRepository devices;
    @NonNull private final DevicePolicy policy;
    @NonNull private final Supplier<TrustedDeviceId> deviceIds;
    @NonNull private final Clock clock;

    /** What the login may issue after a correct password. */
    public sealed interface DeviceRouting {
        /** Trusted primary device, or a channel without device trust: a full ACTIVE session. */
        record FullSession() implements DeviceRouting { }

        /** New, not primary, expired or only registered: a restricted NEED_TRUSTED_DEVICE session. */
        record NeedTrust() implements DeviceRouting { }
    }

    /**
     * DD 20 §2: trusted? → primary? WEB has no device trust. The first device of a customer on a
     * channel is trusted and made primary directly (phase 3); every later device waits for the
     * trust flow (phase 4).
     */
    public DeviceRouting routeAfterPassword(CustomerId customerId, Channel channel, DeviceId deviceId,
                                            DevicePlatform platform, String devicePublicKey, String correlationId) {
        if (channel != Channel.MOBILE) {
            return new DeviceRouting.FullSession();
        }
        Instant now = clock.instant();
        List<TrustedDevice> live = devices.findLive(customerId, channel);
        if (live.isEmpty()) {
            TrustedDevice first = TrustedDevice.trustedNow(deviceIds.get(), customerId, channel, deviceId, platform,
                    devicePublicKey, now, policy);
            return switch (devices.trustFirstDevice(first, correlationId)) {
                case TrustFirstResult.Trusted(var trusted) -> new DeviceRouting.FullSession();
                case TrustFirstResult.AlreadyHasDevice() -> new DeviceRouting.NeedTrust();
            };
        }
        Optional<TrustedDevice> device = live.stream().filter(d -> d.deviceId().equals(deviceId)).findFirst();
        Optional<TrustedDeviceId> primary = devices.findPrimary(customerId, channel);
        if (device.isEmpty() || !device.get().isTrusted(now) || !primary.equals(device.map(TrustedDevice::id))) {
            return new DeviceRouting.NeedTrust();
        }
        devices.saveIfCurrent(device.get().recordLogin(now), correlationId); // display data; a lost race is harmless
        return new DeviceRouting.FullSession();
    }

    /**
     * Keeps the live rows within {@code maxLiveDevices} before a new device is trusted: the oldest
     * by last login are expired (DD 20 §7). Used by the trust flow of phase 4; with the direct path
     * only the first device is ever trusted, so it cannot trigger yet.
     */
    public List<TrustedDevice> expireBeyondCap(List<TrustedDevice> live, String correlationId) {
        int excess = live.size() - policy.maxLiveDevices() + 1;
        if (excess <= 0) {
            return List.of();
        }
        List<TrustedDevice> oldest = live.stream()
                .sorted(Comparator.comparing(d -> d.lastLoginAt() == null ? Instant.EPOCH : d.lastLoginAt()))
                .limit(excess).toList();
        oldest.forEach(device -> devices.saveIfCurrent(device.expire(), correlationId));
        return oldest;
    }

    @Override
    public List<DeviceSummary> list(CustomerId customerId, Channel channel) {
        Optional<TrustedDeviceId> primary = devices.findPrimary(customerId, channel);
        return devices.findLive(customerId, channel).stream()
                .map(device -> DeviceSummary.builder().deviceId(device.deviceId()).platform(device.platform())
                        .status(device.status()).trustLevel(device.trustLevel())
                        .primary(primary.isPresent() && primary.get().equals(device.id()))
                        .trustedAt(device.trustedAt()).expiresAt(device.expiresAt()).lastLoginAt(device.lastLoginAt())
                        .build())
                .toList();
    }
}
