package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.core.port.out.device.RecordDeviceRevocation;
import com.vpbank.dcp.infrastructure.persistence.projection.DeviceRevocationAuditView;
import jakarta.persistence.EntityManager;
import java.sql.Timestamp;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class SecurityAuditPersistenceRepository {
    private final EntityManager entityManager;

    public SecurityAuditPersistenceRepository(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager");
    }

    public DeviceRevocationAuditView findDeviceRevocation(RecordDeviceRevocation command) {
        List<?> rows = entityManager.createNativeQuery(SecurityAuditSql.FIND_DEVICE_REVOKE)
                .setParameter("bindingId", command.bindingId().toString())
                .setParameter("customerId", command.owner().customerId().toString())
                .setParameter("appId", command.owner().appId()).getResultList();
        if (rows.isEmpty()) {
            return null;
        }
        if (rows.size() != 1) {
            throw new UnexpectedDeviceRevocationStateException();
        }
        Object[] row = (Object[]) rows.getFirst();
        return new DeviceRevocationAuditView(UUID.fromString((String) row[0]),
                ((Number) row[1]).longValue(), ((Number) row[2]).intValue() == 1);
    }

    public void insertDeviceRevoked(RecordDeviceRevocation command, long securityVersion) {
        int affected = entityManager.createNativeQuery(SecurityAuditSql.INSERT_DEVICE_REVOKE)
                .setParameter("eventId", UUID.randomUUID().toString())
                .setParameter("customerId", command.owner().customerId().toString())
                .setParameter("appId", command.owner().appId())
                .setParameter("operationId", command.operationId().toString())
                .setParameter("bindingId", command.bindingId().toString())
                .setParameter("deviceSecurityVersion", securityVersion)
                .setParameter("reasonCode", command.reason().code())
                .setParameter("actorType", command.actor().type().code())
                .setParameter("actorId", command.actor().id())
                .setParameter("occurredAt", Timestamp.from(command.occurredAt()))
                .executeUpdate();
        requireOne(affected);
    }

    public void insertPrimaryCleared(RecordDeviceRevocation command) {
        int affected = entityManager.createNativeQuery(SecurityAuditSql.INSERT_PRIMARY_CLEARED)
                .setParameter("eventId", UUID.randomUUID().toString())
                .setParameter("customerId", command.owner().customerId().toString())
                .setParameter("appId", command.owner().appId())
                .setParameter("operationId", command.operationId().toString())
                .setParameter("bindingId", command.bindingId().toString())
                .setParameter("actorType", command.actor().type().code())
                .setParameter("actorId", command.actor().id())
                .setParameter("occurredAt", Timestamp.from(command.occurredAt()))
                .executeUpdate();
        requireOne(affected);
    }

    private static void requireOne(int affected) {
        if (affected != 1) {
            throw new UnexpectedDeviceRevocationStateException();
        }
    }
}
