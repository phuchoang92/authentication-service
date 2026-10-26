package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common.DeviceIdProtection;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.DeviceEnrollmentEntity;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

/**
 * DeviceEnrollment ↔ TRUSTED_DEVICE_ENROLLMENT. The app's device ID is kept only as the HMAC lookup
 * (the aggregate carries it, so reading the row needs the device ID from the restricted session):
 * {@link #toDomain} takes it from the caller. The authorization token digest travels as unpadded
 * base64url in the aggregate and as 32 raw bytes in the row.
 */
public final class DeviceEnrollmentPersistenceMapper {
    private DeviceEnrollmentPersistenceMapper() {
    }

    public static DeviceEnrollmentEntity toEntity(DeviceEnrollment enrollment, SessionId sessionId, DeviceIdProtection protection) {
        byte[] deviceLookup = protection.lookup(enrollment.customerId(), enrollment.channel(), enrollment.deviceId());
        // Only the approval path has a requester distinct in role from the target (slice 6).
        byte[] requesterLookup = enrollment.isApproval() ? deviceLookup : null;

        return DeviceEnrollmentEntity.builder()
                .id(enrollment.id().value())
                .customerId(enrollment.customerId().value())
                .channel(enrollment.channel().name())
                .purpose(enrollment.purpose())
                .state(enrollment.state())
                .targetDeviceId(enrollment.targetDeviceId() == null ? null : enrollment.targetDeviceId().value())
                .actorDeviceId(enrollment.actorDeviceId() == null ? null : enrollment.actorDeviceId().value())
                .targetClientDeviceIdLookup(deviceLookup)
                .requesterClientDeviceIdLookup(requesterLookup)
                .clientDeviceIdLookupKeyId(protection.lookupKeyId())
                .multifactorId(enrollment.mfaTransactionId())
                .confirmedMfaMethod(enrollment.mfaMethod())
                .authorizationAttempts(attemptsOf(enrollment))
                .authorizationTokenDigest(digestBytes(enrollment.authorizationTokenDigest()))
                .authorizationExpiresAt(enrollment.authorizationExpiresAt())
                .authorizationConsumedAt(enrollment.authorizationConsumedAt())
                .expiresAt(enrollment.expiresAt())
                .creationIdempotencyDigest(creationDigest(sessionId))
                .version(enrollment.version())
                .build();
    }

    public static DeviceEnrollment toDomain(DeviceEnrollmentEntity entity, DeviceId deviceId) {
        boolean approval = entity.getPurpose() == EnrollmentPurpose.TRUST_DEVICE_APPROVAL;
        int verifyAttempts = approval ? 0 : entity.getAuthorizationAttempts();
        int claimAttempts = approval ? entity.getAuthorizationAttempts() : 0;

        return DeviceEnrollment.builder()
                .id(new EnrollmentId(entity.getId()))
                .customerId(new CustomerId(entity.getCustomerId()))
                .channel(Channel.valueOf(entity.getChannel()))
                .deviceId(deviceId)
                .purpose(entity.getPurpose())
                .state(entity.getState())
                .targetDeviceId(entity.getTargetDeviceId() == null ? null : new TrustedDeviceId(entity.getTargetDeviceId()))
                .actorDeviceId(entity.getActorDeviceId() == null ? null : new TrustedDeviceId(entity.getActorDeviceId()))
                .mfaTransactionId(entity.getMultifactorId())
                .mfaMethod(entity.getConfirmedMfaMethod())
                .verifyAttempts(verifyAttempts)
                .authorizationTokenDigest(digestText(entity.getAuthorizationTokenDigest()))
                .authorizationExpiresAt(entity.getAuthorizationExpiresAt())
                .authorizationAttempts(claimAttempts)
                .authorizationConsumedAt(entity.getAuthorizationConsumedAt())
                .expiresAt(entity.getExpiresAt())
                .version(entity.getVersion())
                .build();
    }

    /** Copies the step the aggregate decided onto the managed row; {@code mfaConfirmedAt} only when the MFA passed. */
    public static void apply(DeviceEnrollmentEntity entity, DeviceEnrollment changed, Instant mfaConfirmedAt) {
        entity.applyState(
                changed.state(),
                changed.mfaTransactionId(),
                changed.mfaMethod(),
                attemptsOf(changed),
                mfaConfirmedAt);
        if (changed.isApproval()) {
            entity.applyApproval(
                    changed.actorDeviceId() == null ? null : changed.actorDeviceId().value(),
                    digestBytes(changed.authorizationTokenDigest()),
                    changed.authorizationExpiresAt(),
                    changed.authorizationConsumedAt());
        }
    }

    /** SHA-256 of the restricted session ID: one enrollment per session and purpose, no secret needed. */
    public static byte[] creationDigest(SessionId sessionId) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(sessionId.value().toString().getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is not available", failure);
        }
    }

    /** One counter column serves both purposes (see the entity): challenge answers, or QR token claims. */
    private static int attemptsOf(DeviceEnrollment enrollment) {
        if (enrollment.isApproval()) {
            return enrollment.authorizationAttempts();
        }
        return enrollment.verifyAttempts();
    }

    private static byte[] digestBytes(String base64Url) {
        if (base64Url == null) {
            return null;
        }
        return Base64.getUrlDecoder().decode(base64Url);
    }

    private static String digestText(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
