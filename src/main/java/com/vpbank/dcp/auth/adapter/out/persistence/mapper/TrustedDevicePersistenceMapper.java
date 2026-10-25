package com.vpbank.dcp.auth.adapter.out.persistence.mapper;

import com.vpbank.dcp.auth.adapter.out.persistence.common.DeviceIdProtection;
import com.vpbank.dcp.auth.adapter.out.persistence.entity.PrimaryTrustedDeviceEntity;
import com.vpbank.dcp.auth.adapter.out.persistence.entity.TrustedDeviceAuditEntity;
import com.vpbank.dcp.auth.adapter.out.persistence.entity.TrustedDeviceEntity;
import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/** TrustedDevice aggregate ↔ phase-3 rows. The device ID is protected on the way in and recovered on the way out. */
public final class TrustedDevicePersistenceMapper {
    public static final String POLICY_VERSION = "td-p3-v1";

    private TrustedDevicePersistenceMapper() {
    }

    public static TrustedDeviceEntity toEntity(TrustedDevice device, DeviceIdProtection protection) {
        boolean hasKey = device.publicKey() != null;
        return TrustedDeviceEntity.builder()
                .id(device.id().value())
                .customerId(device.customerId().value())
                .channel(device.channel().name())
                .clientDeviceIdLookup(protection.lookup(device.customerId(), device.channel(), device.deviceId()))
                .clientDeviceIdLookupKeyId(protection.lookupKeyId())
                .clientDeviceIdCiphertext(protection.encrypt(device.customerId(), device.channel(), device.deviceId()))
                .clientDeviceIdKeyId(protection.encryptionKeyId())
                .platform(device.platform())
                .status(device.status())
                .trustLevel(device.trustLevel())
                .trustedAt(device.trustedAt())
                .expiresAt(device.expiresAt())
                .lastSuccessfulLoginAt(device.lastLoginAt())
                .primaryCryptoSuite(hasKey ? TrustedDeviceEntity.JWK_SUITE : null)
                .primaryPublicKey(device.publicKey())
                .primaryKeyId(hasKey ? device.id().value().toString() : null)
                .version(device.version())
                .build();
    }

    /** Empty when the ciphertext cannot be opened: an unknown key or a tampered row is "no device", never a guess. */
    public static Optional<TrustedDevice> toDomain(TrustedDeviceEntity entity, DeviceIdProtection protection) {
        CustomerId customerId = new CustomerId(entity.getCustomerId());
        Channel channel = Channel.valueOf(entity.getChannel());
        return protection.decrypt(entity.getClientDeviceIdKeyId(), entity.getClientDeviceIdCiphertext(), customerId, channel)
                .map(deviceId -> TrustedDevice.builder()
                        .id(new TrustedDeviceId(entity.getId()))
                        .customerId(customerId)
                        .channel(channel)
                        .deviceId(deviceId)
                        .platform(entity.getPlatform())
                        .status(entity.getStatus())
                        .trustLevel(entity.getTrustLevel())
                        .trustedAt(entity.getTrustedAt())
                        .expiresAt(entity.getExpiresAt())
                        .lastLoginAt(entity.getLastSuccessfulLoginAt())
                        .publicKey(entity.getPrimaryPublicKey())
                        .version(entity.getVersion())
                        .build());
    }

    public static void apply(TrustedDeviceEntity entity, TrustedDevice changed) {
        entity.applyState(changed.status(), changed.trustLevel(), changed.trustedAt(), changed.expiresAt(),
                changed.lastLoginAt());
    }

    public static PrimaryTrustedDeviceEntity toPrimary(TrustedDevice device, Instant assignedAt) {
        return PrimaryTrustedDeviceEntity.builder()
                .key(new PrimaryTrustedDeviceEntity.Key(device.customerId().value(), device.channel().name()))
                .primaryDeviceId(device.id().value())
                .assignedAt(assignedAt)
                .build();
    }

    public static TrustedDeviceAuditEntity toAudit(TrustedDevice device, String correlationId, int sequence,
                                                   String eventType, String cause, String reasonCode, Instant occurredAt) {
        return TrustedDeviceAuditEntity.builder()
                .id(UUID.randomUUID())
                .customerId(device.customerId().value())
                .correlationId(correlationId)
                .eventSequence(sequence)
                .eventType(eventType)
                .cause(cause)
                .actorType("CUSTOMER")
                .actorSubject(device.customerId().value())
                .actorDeviceId(device.id().value())
                .actorChannel(device.channel().name())
                .targetDeviceId(device.id().value())
                .targetChannel(device.channel().name())
                .targetAction(eventType)
                .reasonCode(reasonCode)
                .policyVersion(POLICY_VERSION)
                .occurredAt(occurredAt)
                .build();
    }
}
