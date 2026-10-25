package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper;

import com.vpbank.dcp.auth.domain.enums.Channel;
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

/**
 * DeviceEnrollment ↔ TRUSTED_DEVICE_ENROLLMENT. The app's device ID is kept only as the HMAC lookup
 * (the aggregate carries it, so reading the row needs the device ID from the restricted session):
 * {@link #toDomain} takes it from the caller.
 */
public final class DeviceEnrollmentPersistenceMapper {
    private DeviceEnrollmentPersistenceMapper() {
    }

    public static DeviceEnrollmentEntity toEntity(DeviceEnrollment enrollment, SessionId sessionId, DeviceIdProtection protection) {
        return DeviceEnrollmentEntity.builder()
                .id(enrollment.id().value())
                .customerId(enrollment.customerId().value())
                .channel(enrollment.channel().name())
                .purpose(enrollment.purpose())
                .state(enrollment.state())
                .targetDeviceId(enrollment.targetDeviceId() == null ? null : enrollment.targetDeviceId().value())
                .targetClientDeviceIdLookup(protection.lookup(enrollment.customerId(), enrollment.channel(), enrollment.deviceId()))
                .clientDeviceIdLookupKeyId(protection.lookupKeyId())
                .multifactorId(enrollment.mfaTransactionId())
                .authorizationAttempts(enrollment.verifyAttempts())
                .expiresAt(enrollment.expiresAt())
                .creationIdempotencyDigest(creationDigest(sessionId))
                .version(enrollment.version())
                .build();
    }

    public static DeviceEnrollment toDomain(DeviceEnrollmentEntity entity, DeviceId deviceId) {
        return DeviceEnrollment.builder()
                .id(new EnrollmentId(entity.getId()))
                .customerId(new CustomerId(entity.getCustomerId()))
                .channel(Channel.valueOf(entity.getChannel()))
                .deviceId(deviceId)
                .purpose(entity.getPurpose())
                .state(entity.getState())
                .targetDeviceId(entity.getTargetDeviceId() == null ? null : new TrustedDeviceId(entity.getTargetDeviceId()))
                .mfaTransactionId(entity.getMultifactorId())
                .verifyAttempts(entity.getAuthorizationAttempts())
                .expiresAt(entity.getExpiresAt())
                .version(entity.getVersion())
                .build();
    }

    public static void apply(DeviceEnrollmentEntity entity, DeviceEnrollment changed, Instant mfaConfirmedAt) {
        entity.applyState(changed.state(), changed.mfaTransactionId(), changed.verifyAttempts(), mfaConfirmedAt);
    }

    /** SHA-256 of the restricted session ID: one enrollment per session, no secret needed. */
    public static byte[] creationDigest(SessionId sessionId) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(sessionId.value().toString().getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is not available", failure);
        }
    }
}
