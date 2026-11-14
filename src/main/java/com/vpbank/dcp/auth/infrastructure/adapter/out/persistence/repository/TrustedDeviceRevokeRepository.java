package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.application.port.out.model.DeviceRevocation;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceEntity;
import jakarta.persistence.EntityManager;
import java.nio.ByteBuffer;
import java.util.UUID;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/** Copies the protected values directly so a revoke preserves the original binding snapshot. */
@RequiredArgsConstructor
public final class TrustedDeviceRevokeRepository {
    @NonNull private final EntityManager entityManager;

    public int snapshot(TrustedDeviceEntity binding) {
        return entityManager.createNativeQuery(TrustedDeviceRevokeSql.SNAPSHOT_BINDING)
                .setParameter("id", bytesOf(binding.getId()))
                .setParameter("customerId", binding.getCustomerId())
                .setParameter("channel", binding.getChannel())
                .setParameter("version", binding.getVersion())
                .executeUpdate();
    }

    public boolean contains(DeviceRevocation command) {
        Number matches = (Number) entityManager.createNativeQuery(TrustedDeviceRevokeSql.COUNT_OWNED_SNAPSHOT)
                .setParameter("id", bytesOf(command.targetBindingId().value()))
                .setParameter("customerId", command.customerId().value())
                .setParameter("channel", command.channel().name())
                .getSingleResult();
        return matches.longValue() == 1;
    }

    private static byte[] bytesOf(UUID id) {
        return ByteBuffer.allocate(16)
                .putLong(id.getMostSignificantBits())
                .putLong(id.getLeastSignificantBits())
                .array();
    }
}
