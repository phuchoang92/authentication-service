package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.core.port.out.device.RecordDeviceRevocation;
import com.vpbank.dcp.infrastructure.persistence.projection.TrustedDeviceAppView;
import com.vpbank.dcp.infrastructure.persistence.projection.TrustedDeviceStateView;
import jakarta.persistence.EntityManager;
import java.sql.Timestamp;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class TrustedDeviceRevocationPersistenceRepository {
    private final EntityManager entityManager;

    public TrustedDeviceRevocationPersistenceRepository(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager");
    }

    public TrustedDeviceAppView lockCustomerApp(RecordDeviceRevocation command) {
        List<?> rows = entityManager.createNativeQuery(TrustedDeviceRevocationSql.LOCK_CUSTOMER_APP)
                .setParameter("customerId", command.owner().customerId().toString())
                .setParameter("appId", command.owner().appId()).getResultList();
        if (rows.isEmpty()) {
            return null;
        }
        Object[] row = onlyRow(rows);
        UUID primary = row[0] == null ? null : UUID.fromString((String) row[0]);
        return new TrustedDeviceAppView(primary, ((Number) row[1]).longValue());
    }

    public TrustedDeviceStateView lockDevice(RecordDeviceRevocation command) {
        List<?> rows = entityManager.createNativeQuery(TrustedDeviceRevocationSql.LOCK_DEVICE)
                .setParameter("bindingId", command.bindingId().toString())
                .setParameter("customerId", command.owner().customerId().toString())
                .setParameter("appId", command.owner().appId()).getResultList();
        if (rows.isEmpty()) {
            return null;
        }
        Object[] row = onlyRow(rows);
        return new TrustedDeviceStateView((String) row[0],
                ((Number) row[1]).longValue(), ((Number) row[2]).longValue());
    }

    public int markRevoked(RecordDeviceRevocation command) {
        return entityManager.createNativeQuery(TrustedDeviceRevocationSql.REVOKE_DEVICE)
                .setParameter("bindingId", command.bindingId().toString())
                .setParameter("customerId", command.owner().customerId().toString())
                .setParameter("appId", command.owner().appId())
                .setParameter("expectedVersion", command.expectedVersion())
                .setParameter("occurredAt", Timestamp.from(command.occurredAt()))
                .setParameter("reasonCode", command.reason().code())
                .setParameter("actorType", command.actor().type().code())
                .setParameter("actorId", command.actor().id()).executeUpdate();
    }

    public int clearPrimary(RecordDeviceRevocation command, long expectedAppVersion) {
        return entityManager.createNativeQuery(TrustedDeviceRevocationSql.CLEAR_PRIMARY)
                .setParameter("bindingId", command.bindingId().toString())
                .setParameter("customerId", command.owner().customerId().toString())
                .setParameter("appId", command.owner().appId())
                .setParameter("expectedVersion", expectedAppVersion).executeUpdate();
    }

    private static Object[] onlyRow(List<?> rows) {
        if (rows.size() != 1) {
            throw new UnexpectedDeviceRevocationStateException();
        }
        return (Object[]) rows.getFirst();
    }
}
