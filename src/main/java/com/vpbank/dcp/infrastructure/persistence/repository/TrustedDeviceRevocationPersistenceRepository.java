package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.core.port.out.device.RecordDeviceRevocation;
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

    public boolean lockCustomer(RecordDeviceRevocation command) {
        List<?> rows = entityManager.createNativeQuery(TrustedDeviceRevocationSql.LOCK_CUSTOMER)
                .setParameter("customerId", command.owner().customerId().toString())
                .getResultList();
        if (rows.isEmpty()) {
            return false;
        }
        onlyRow(rows);
        return true;
    }

    public UUID findPrimary(RecordDeviceRevocation command) {
        List<?> rows = entityManager.createNativeQuery(TrustedDeviceRevocationSql.FIND_PRIMARY)
                .setParameter("customerId", command.owner().customerId().toString())
                .setParameter("channel", command.owner().channel()).getResultList();
        if (rows.isEmpty()) {
            return null;
        }
        return UUID.fromString((String) onlyRow(rows));
    }

    public TrustedDeviceStateView lockDevice(RecordDeviceRevocation command) {
        List<?> rows = entityManager.createNativeQuery(TrustedDeviceRevocationSql.LOCK_DEVICE)
                .setParameter("bindingId", command.bindingId().toString())
                .setParameter("customerId", command.owner().customerId().toString())
                .setParameter("channel", command.owner().channel()).getResultList();
        if (rows.isEmpty()) {
            return null;
        }
        Object[] row = (Object[]) onlyRow(rows);
        return new TrustedDeviceStateView((String) row[0],
                ((Number) row[1]).longValue(), ((Number) row[2]).longValue());
    }

    public int markRevoked(RecordDeviceRevocation command) {
        return entityManager.createNativeQuery(TrustedDeviceRevocationSql.REVOKE_DEVICE)
                .setParameter("bindingId", command.bindingId().toString())
                .setParameter("customerId", command.owner().customerId().toString())
                .setParameter("channel", command.owner().channel())
                .setParameter("expectedVersion", command.expectedVersion())
                .setParameter("occurredAt", Timestamp.from(command.occurredAt()))
                .setParameter("reasonCode", command.reason().code())
                .setParameter("actorType", command.actor().type().code())
                .setParameter("actorId", command.actor().id()).executeUpdate();
    }

    private static Object onlyRow(List<?> rows) {
        if (rows.size() != 1) {
            throw new UnexpectedDeviceRevocationStateException();
        }
        return rows.getFirst();
    }
}
