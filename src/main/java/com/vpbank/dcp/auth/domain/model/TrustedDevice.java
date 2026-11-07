package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.TrustLevel;
import com.vpbank.dcp.auth.domain.exception.DeviceStateException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import lombok.Builder;
import lombok.NonNull;

/**
 * One app installation known for a customer on a channel (a TRUSTED_DEVICE row). Trust means
 * ACTIVE + TRUSTED + not expired; being primary is recorded on the customer, not here.
 * {@code publicKey} is the device's public signing JWK as the app sent it at enrollment (ML-DSA-65 from
 * slice 13 on, P-256 before); a trusted device proves it at every login (slice 13). {@code version} is the row version the repository must still see when saving.
 */
@Builder(toBuilder = true)
public record TrustedDevice(@NonNull TrustedDeviceId id,
                            @NonNull CustomerId customerId,
                            @NonNull Channel channel,
                            @NonNull DeviceId deviceId,
                            @NonNull DevicePlatform platform,
                            @NonNull DeviceStatus status,
                            @NonNull TrustLevel trustLevel,
                            Instant trustedAt,
                            @NonNull Instant expiresAt,
                            Instant lastLoginAt,
                            String publicKey,
                            long version) {
    public TrustedDevice {
        if ((trustLevel == TrustLevel.TRUSTED) == (trustedAt == null)) {
            throw new IllegalArgumentException("TRUSTED and the trust time are set together");
        }
    }

    /**
     * The enrollment flow confirmed this installation (DD 20 §4): a new ACTIVE/TRUSTED row with the key
     * the device proved, trusted from its creation for the policy's trust duration. A previous live row of the
     * same installation is replaced by the repository.
     */
    public static TrustedDevice trustedByEnrollment(@NonNull NewDevice newDevice, @NonNull DevicePolicy policy) {
        Instant trustedAt = newDevice.createdAt();
        return rowOf(newDevice)
                .status(DeviceStatus.ACTIVE)
                .trustLevel(TrustLevel.TRUSTED)
                .trustedAt(trustedAt)
                .expiresAt(trustedAt.plus(policy.trustDuration()))
                .lastLoginAt(trustedAt)
                .build();
    }

    /**
     * A new installation waiting for the primary device's approval (slice 6): a live row that is not
     * trusted. It holds the key the device sent so the approval can trust exactly that key; it expires
     * with the approval window unless the claim succeeds.
     */
    public static TrustedDevice pending(@NonNull NewDevice newDevice, @NonNull Duration pendingWindow) {
        return rowOf(newDevice)
                .status(DeviceStatus.PENDING)
                .trustLevel(TrustLevel.NONE)
                .trustedAt(null)
                .expiresAt(newDevice.createdAt().plus(pendingWindow))
                .lastLoginAt(null)
                .build();
    }

    /** The fields every new row starts with: who and what it is, the presented key, version 0. */
    private static TrustedDeviceBuilder rowOf(NewDevice newDevice) {
        DeviceInstallation installation = newDevice.installation();
        return TrustedDevice.builder()
                .id(newDevice.id())
                .customerId(installation.customerId())
                .channel(installation.channel())
                .deviceId(installation.deviceId())
                .platform(newDevice.key().platform())
                .publicKey(newDevice.key().publicJwk())
                .version(0);
    }

    /**
     * The primary device approved this installation and the QR token was claimed: a live row (PENDING, or an
     * already trusted but not primary row) becomes trusted from now with the key it holds.
     */
    public TrustedDevice trustByApproval(Instant now, DevicePolicy policy) {
        if (!status.live()) {
            throw new DeviceStateException("Device is " + status);
        }
        Objects.requireNonNull(publicKey, "publicKey");
        Instant trustExpiresAt = now.plus(policy.trustDuration());
        return toBuilder()
                .status(DeviceStatus.ACTIVE)
                .trustLevel(TrustLevel.TRUSTED)
                .trustedAt(now)
                .expiresAt(trustExpiresAt)
                .lastLoginAt(now)
                .build();
    }

    public boolean isPending() {
        return status == DeviceStatus.PENDING;
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
