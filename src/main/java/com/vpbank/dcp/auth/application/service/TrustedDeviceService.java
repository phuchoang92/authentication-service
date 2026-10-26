package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.in.ListDevicesUseCase;
import com.vpbank.dcp.auth.application.port.out.model.TrustConfirmation;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository.RegisterPendingResult;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository.TrustFirstResult;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.application.result.DeviceSummary;
import com.vpbank.dcp.auth.application.result.KnownDeviceSummary;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.PrimaryMode;
import com.vpbank.dcp.auth.domain.exception.DeviceStateException;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Owns the device rules (ARCHITECTURE §6.1): which installation is trusted, which is primary, and
 * the direct trust of a customer's first device. {@link LoginService} calls it after the password
 * is verified and decides the session from the answer; it never touches device rows itself.
 */
@RequiredArgsConstructor
public final class TrustedDeviceService implements ListDevicesUseCase {
    /** Devices that never logged in sort as the oldest when the cap chooses what to expire. */
    private static final Comparator<TrustedDevice> OLDEST_LOGIN_FIRST =
            Comparator.comparing(device -> device.lastLoginAt() == null ? Instant.EPOCH : device.lastLoginAt());

    @NonNull private final TrustedDeviceRepository trustedDeviceRepository;
    @NonNull private final DevicePolicy devicePolicy;
    @NonNull private final Supplier<TrustedDeviceId> trustedDeviceIdGenerator;
    @NonNull private final Clock clock;

    /** What the login may issue after a correct password. */
    public sealed interface DeviceRouting {
        /** Trusted primary device, or a channel without device trust: a full ACTIVE session. */
        record FullSession() implements DeviceRouting {
        }

        /** New, not primary, expired or only registered: a restricted NEED_TRUSTED_DEVICE session. */
        record NeedTrust() implements DeviceRouting {
        }
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

        List<TrustedDevice> liveTrustedDevices = trustedDeviceRepository.findLive(customerId, channel);
        if (liveTrustedDevices.isEmpty()) {
            return trustFirstDevice(customerId, channel, deviceId, platform, devicePublicKey, now, correlationId);
        }

        Optional<TrustedDevice> thisDevice = findByDeviceId(liveTrustedDevices, deviceId);
        Optional<TrustedDeviceId> primaryDeviceId = trustedDeviceRepository.findPrimary(customerId, channel);
        if (thisDevice.isEmpty()) {
            return new DeviceRouting.NeedTrust();
        }
        TrustedDevice device = thisDevice.get();

        if (!device.isTrusted(now)) {
            return new DeviceRouting.NeedTrust();
        }

        boolean isPrimary = primaryDeviceId.isPresent() && primaryDeviceId.get().equals(device.id());
        if (!isPrimary) {
            return new DeviceRouting.NeedTrust();
        }

        // Display data only: a lost race against another login is harmless.
        TrustedDevice deviceWithLogin = device.recordLogin(now);
        trustedDeviceRepository.saveIfCurrent(deviceWithLogin, correlationId);

        return new DeviceRouting.FullSession();
    }

    private DeviceRouting trustFirstDevice(CustomerId customerId, Channel channel, DeviceId deviceId,
                                           DevicePlatform platform, String devicePublicKey, Instant now,
                                           String correlationId) {
        TrustedDevice firstDevice = TrustedDevice.trustedNow(
                trustedDeviceIdGenerator.get(),
                customerId,
                channel,
                deviceId,
                platform,
                devicePublicKey,
                now,
                devicePolicy);

        TrustFirstResult trustFirstResult = trustedDeviceRepository.trustFirstDevice(firstDevice, correlationId);
        return switch (trustFirstResult) {
            case TrustFirstResult.Trusted(TrustedDevice trustedDevice) -> new DeviceRouting.FullSession();
            case TrustFirstResult.AlreadyHasDevice() -> new DeviceRouting.NeedTrust();
        };
    }

    /**
     * Keeps the live rows within {@code maxLiveDevices} before a new device is trusted: the oldest
     * by last login are expired (DD 20 §7). Used by the trust flow of phase 4; with the direct path
     * only the first device is ever trusted, so it cannot trigger yet.
     */
    public List<TrustedDevice> expireBeyondCap(List<TrustedDevice> liveTrustedDevices, String correlationId) {
        List<TrustedDevice> oldestBeyondCap = oldestBeyondCap(liveTrustedDevices);

        for (TrustedDevice oldDevice : oldestBeyondCap) {
            TrustedDevice expiredDevice = oldDevice.expire();
            trustedDeviceRepository.saveIfCurrent(expiredDevice, correlationId);
        }

        return oldestBeyondCap;
    }

    /** What another service may know about a live installation (never the aggregate). */
    public Optional<KnownDeviceSummary> knownDevice(CustomerId customerId, Channel channel, DeviceId deviceId) {
        Optional<TrustedDevice> liveDevice = trustedDeviceRepository.findLive(customerId, channel, deviceId);

        return liveDevice.map(device -> new KnownDeviceSummary(
                device.id(),
                device.platform(),
                device.publicKey()));
    }

    /**
     * The enrollment flow passed FACE (DD 20 §4): this installation becomes trusted with the key it
     * proved and the customer's primary on the channel. A previous live row of the same installation
     * is replaced (a reinstall or a re-trust), the device cap is enforced, and everything is written in
     * one transaction with the enrollment and its audit trail. The old primary stays trusted (§7).
     */
    public TrustedDevice confirmTrust(DeviceEnrollment enrollment, DevicePlatform platform, String devicePublicJwk,
                                      String receiptDigest, String correlationId) {
        Instant now = clock.instant();

        List<TrustedDevice> liveTrustedDevices =
                trustedDeviceRepository.findLive(enrollment.customerId(), enrollment.channel());

        Optional<TrustedDevice> replacedDevice = findByDeviceId(liveTrustedDevices, enrollment.deviceId());

        List<TrustedDevice> otherLiveDevices = new ArrayList<>(liveTrustedDevices);
        replacedDevice.ifPresent(otherLiveDevices::remove);

        List<TrustedDevice> devicesExpiredByCap = expireOldestBeyondCap(otherLiveDevices);

        TrustedDevice newTrustedDevice = TrustedDevice.trustedByEnrollment(
                trustedDeviceIdGenerator.get(),
                enrollment.customerId(),
                enrollment.channel(),
                enrollment.deviceId(),
                platform,
                devicePublicJwk,
                now,
                devicePolicy);

        TrustedDevice expiredReplacedDevice = replacedDevice
                .map(TrustedDevice::expire)
                .orElse(null);

        DeviceEnrollment completedEnrollment = enrollment.complete();

        TrustConfirmation trustConfirmation = TrustConfirmation.builder()
                .device(newTrustedDevice)
                .replaced(expiredReplacedDevice)
                .expiredByCap(devicesExpiredByCap)
                .enrollment(completedEnrollment)
                .primaryMode(PrimaryMode.FACE_CONFIRMED)
                .faceAuthenticated(true)
                .receiptDigest(receiptDigest)
                .build();

        return trustedDeviceRepository.trustConfirmed(
                trustConfirmation,
                correlationId);
    }

    /**
     * Slice 6: a new installation asks to be approved by the primary device. Its public key and platform are
     * kept on a PENDING live row until the claim; a known live row of the same installation is reused as is.
     * Empty when the customer already has the maximum number of installations waiting.
     */
    public Optional<TrustedDevice> registerPendingDevice(CustomerId customerId, Channel channel, DeviceId deviceId,
                                                         DevicePlatform platform, String devicePublicJwk,
                                                         EnrollmentPolicy enrollmentPolicy, String correlationId) {
        Optional<TrustedDevice> knownLiveDevice = trustedDeviceRepository.findLive(customerId, channel, deviceId);
        if (knownLiveDevice.isPresent()) {
            return knownLiveDevice;
        }

        int pendingDevices = trustedDeviceRepository.countPending(customerId, channel);
        if (pendingDevices >= enrollmentPolicy.maxPendingDevices()) {
            return Optional.empty();
        }

        TrustedDevice pendingDevice = TrustedDevice.pending(
                trustedDeviceIdGenerator.get(),
                customerId,
                channel,
                deviceId,
                platform,
                devicePublicJwk,
                clock.instant(),
                enrollmentPolicy.pendingWindow());

        RegisterPendingResult registerResult = trustedDeviceRepository.registerPending(pendingDevice, correlationId);
        return switch (registerResult) {
            case RegisterPendingResult.Registered(TrustedDevice registeredDevice) -> Optional.of(registeredDevice);
            // another login of the same installation registered first: its row is the target
            case RegisterPendingResult.InstallationAlreadyLive() ->
                    trustedDeviceRepository.findLive(customerId, channel, deviceId);
        };
    }

    /** This installation's row ID when it is the customer's trusted primary on the channel; empty otherwise. */
    public Optional<TrustedDeviceId> primaryDeviceId(CustomerId customerId, Channel channel, DeviceId deviceId) {
        Instant now = clock.instant();

        Optional<TrustedDevice> liveDevice = trustedDeviceRepository.findLive(customerId, channel, deviceId);
        if (liveDevice.isEmpty() || !liveDevice.get().isTrusted(now)) {
            return Optional.empty();
        }

        Optional<TrustedDeviceId> primaryDeviceId = trustedDeviceRepository.findPrimary(customerId, channel);
        boolean isPrimary = primaryDeviceId.isPresent() && primaryDeviceId.get().equals(liveDevice.get().id());
        if (!isPrimary) {
            return Optional.empty();
        }
        return Optional.of(liveDevice.get().id());
    }

    /**
     * Slice 6: the primary device approved this installation and the QR token was claimed. The target row
     * (PENDING, or a known live row) becomes trusted and the customer's primary on the channel in one
     * transaction with the completed enrollment and the audit trail. The old primary stays trusted (§7).
     */
    public TrustedDevice confirmTrustByApproval(DeviceEnrollment consumedEnrollment, String correlationId) {
        Instant now = clock.instant();

        List<TrustedDevice> liveDevices =
                trustedDeviceRepository.findLive(consumedEnrollment.customerId(), consumedEnrollment.channel());

        TrustedDevice targetDevice = liveDevices.stream()
                .filter(device -> device.id().equals(consumedEnrollment.targetDeviceId()))
                .findFirst()
                .orElseThrow(() -> new DeviceStateException("The approved device row is no longer live"));

        List<TrustedDevice> otherLiveDevices = new ArrayList<>(liveDevices);
        otherLiveDevices.remove(targetDevice);

        List<TrustedDevice> devicesExpiredByCap = expireOldestBeyondCap(otherLiveDevices);

        TrustedDevice approvedDevice = targetDevice.trustByApproval(now, devicePolicy);

        TrustConfirmation trustConfirmation = TrustConfirmation.builder()
                .device(approvedDevice)
                .replaced(null)
                .expiredByCap(devicesExpiredByCap)
                .enrollment(consumedEnrollment)
                .primaryMode(PrimaryMode.OLD_DEVICE_APPROVAL)
                .faceAuthenticated(false)
                .actorDeviceId(consumedEnrollment.actorDeviceId())
                .build();

        return trustedDeviceRepository.trustConfirmed(
                trustConfirmation,
                correlationId);
    }

    /** The expired copies of the rows that must go so that one more device fits under the cap. */
    private List<TrustedDevice> expireOldestBeyondCap(List<TrustedDevice> otherLiveDevices) {
        List<TrustedDevice> devicesExpiredByCap = new ArrayList<>();
        for (TrustedDevice oldDevice : oldestBeyondCap(otherLiveDevices)) {
            devicesExpiredByCap.add(oldDevice.expire());
        }
        return devicesExpiredByCap;
    }

    @Override
    public List<DeviceSummary> list(CustomerId customerId, Channel channel) {
        Optional<TrustedDeviceId> primaryDeviceId = trustedDeviceRepository.findPrimary(customerId, channel);
        List<TrustedDevice> liveTrustedDevices = trustedDeviceRepository.findLive(customerId, channel);

        List<DeviceSummary> summaries = new ArrayList<>();
        for (TrustedDevice device : liveTrustedDevices) {
            boolean isPrimary = primaryDeviceId.isPresent() && primaryDeviceId.get().equals(device.id());
            DeviceSummary summary = DeviceSummary.builder()
                    .deviceId(device.deviceId())
                    .platform(device.platform())
                    .status(device.status())
                    .trustLevel(device.trustLevel())
                    .primary(isPrimary)
                    .trustedAt(device.trustedAt())
                    .expiresAt(device.expiresAt())
                    .lastLoginAt(device.lastLoginAt())
                    .build();
            summaries.add(summary);
        }
        return List.copyOf(summaries);
    }

    /** The live rows that must go so that one more device fits under the cap; empty when it already fits. */
    private List<TrustedDevice> oldestBeyondCap(List<TrustedDevice> liveTrustedDevices) {
        int excessAfterNewDevice = liveTrustedDevices.size() - devicePolicy.maxLiveDevices() + 1;
        if (excessAfterNewDevice <= 0) {
            return List.of();
        }
        return liveTrustedDevices.stream()
                .sorted(OLDEST_LOGIN_FIRST)
                .limit(excessAfterNewDevice)
                .toList();
    }

    private static Optional<TrustedDevice> findByDeviceId(List<TrustedDevice> devices, DeviceId deviceId) {
        return devices.stream()
                .filter(device -> device.deviceId().equals(deviceId))
                .findFirst();
    }
}
