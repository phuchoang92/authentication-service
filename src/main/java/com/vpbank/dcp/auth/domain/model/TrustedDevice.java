package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.TrustLevel;
import com.vpbank.dcp.auth.domain.exception.DeviceStateException;
import java.time.Instant;
import java.util.Objects;
import lombok.Builder;

/**
 * One app installation known for a customer on a channel (a TRUSTED_DEVICE row). Trust means
 * ACTIVE + TRUSTED + not expired; being primary is recorded on the customer, not here.
 * {@code publicKey} is the device's P-256 JWK when the app sent one (possession is proven in a
 * later phase). {@code version} is the row version the repository must still see when saving.
 */
@Builder(toBuilder = true)
public record TrustedDevice(TrustedDeviceId id, CustomerId customerId, Channel channel, DeviceId deviceId,
                            DevicePlatform platform, DeviceStatus status, TrustLevel trustLevel,
                            Instant trustedAt, Instant expiresAt, Instant lastLoginAt, String publicKey,
                            long version) {
    public TrustedDevice {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(trustLevel, "trustLevel");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if ((trustLevel == TrustLevel.TRUSTED) != (trustedAt != null)) {
            throw new IllegalArgumentException("TRUSTED and the trust time are set together");
        }
    }

    /** The first device of a customer on a channel: trusted directly at the first successful login (phase 3). */
    public static TrustedDevice trustedNow(TrustedDeviceId id, CustomerId customerId, Channel channel, DeviceId deviceId,
                                           DevicePlatform platform, String publicKey, Instant now, DevicePolicy policy) {
        Instant trustExpiresAt = now.plus(policy.trustDuration());
        return TrustedDevice.builder()
                .id(id)
                .customerId(customerId)
                .channel(channel)
                .deviceId(deviceId)
                .platform(platform)
                .status(DeviceStatus.ACTIVE)
                .trustLevel(TrustLevel.TRUSTED)
                .trustedAt(now)
                .expiresAt(trustExpiresAt)
                .lastLoginAt(now)
                .publicKey(publicKey)
                .version(0)
                .build();
    }

    /**
     * The enrollment flow confirmed this installation (DD 20 §4): a new ACTIVE/TRUSTED row with the key
     * the device proved. A previous live row of the same installation is replaced by the repository.
     */
    public static TrustedDevice trustedByEnrollment(TrustedDeviceId id, CustomerId customerId, Channel channel,
                                                    DeviceId deviceId, DevicePlatform platform, String publicKey,
                                                    Instant now, DevicePolicy policy) {
        Objects.requireNonNull(publicKey, "publicKey");
        return trustedNow(id, customerId, channel, deviceId, platform, publicKey, now, policy);
    }

    public boolean isTrusted(Instant now) {
        return status == DeviceStatus.ACTIVE && trustLevel == TrustLevel.TRUSTED && now.isBefore(expiresAt);
    }

    /** A successful login on this device; display data only, trust and expiry are untouched. */
    public TrustedDevice recordLogin(Instant now) {
        if (!status.live()) {
            throw new DeviceStateException("Device is " + status);
        }
        return toBuilder().lastLoginAt(now).build();
    }

    /** Trust ran out or the device cap pushed it out; the row becomes history (LIVE_SLOT NULL). */
    public TrustedDevice expire() {
        if (!status.live()) {
            throw new DeviceStateException("Device is already " + status);
        }
        return toBuilder().status(DeviceStatus.EXPIRED).build();
    }
}
