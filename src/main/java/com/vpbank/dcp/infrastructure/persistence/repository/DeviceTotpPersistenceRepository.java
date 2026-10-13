package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.core.port.out.totp.CheckDeviceTotp;
import com.vpbank.dcp.infrastructure.persistence.projection.DeviceTotpCredentialView;
import jakarta.persistence.EntityManager;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class DeviceTotpPersistenceRepository {
    private final EntityManager entityManager;

    public DeviceTotpPersistenceRepository(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager");
    }

    public boolean lockActiveDevice(CheckDeviceTotp command) {
        List<?> rows = entityManager.createNativeQuery(DeviceTotpSql.LOCK_ACTIVE_DEVICE)
                .setParameter("bindingId", command.bindingId().toString())
                .setParameter("customerId", command.owner().customerId().toString())
                .setParameter("channel", command.owner().channel()).getResultList();
        return rows.size() == 1;
    }

    public DeviceTotpCredentialView lockActiveCredential(UUID bindingId) {
        List<?> rows = entityManager.createNativeQuery(DeviceTotpSql.LOCK_ACTIVE_CREDENTIAL)
                .setParameter("bindingId", bindingId.toString()).getResultList();
        if (rows.isEmpty()) {
            return null;
        }
        if (rows.size() != 1) {
            throw new UnexpectedDeviceTotpStateException();
        }
        Object[] row = (Object[]) rows.getFirst();
        Instant blockedUntil = row[5] == null ? null : ((Timestamp) row[5]).toInstant();
        return new DeviceTotpCredentialView(UUID.fromString((String) row[0]),
                (byte[]) row[1], (String) row[2], ((Number) row[3]).longValue(),
                ((Number) row[4]).intValue(), blockedUntil, ((Number) row[6]).longValue());
    }

    public boolean consumeStep(UUID bindingId, UUID credentialId, long matchedStep,
                               long expectedVersion) {
        int changed = entityManager.createNativeQuery(DeviceTotpSql.CONSUME_STEP)
                .setParameter("bindingId", bindingId.toString())
                .setParameter("credentialId", credentialId.toString())
                .setParameter("matchedStep", matchedStep)
                .setParameter("expectedVersion", expectedVersion).executeUpdate();
        return changed == 1;
    }

    public boolean recordFailure(UUID bindingId, UUID credentialId, long expectedVersion,
                                 int failedAttempts, Instant blockedUntil) {
        int changed = entityManager.createNativeQuery(DeviceTotpSql.RECORD_FAILURE)
                .setParameter("bindingId", bindingId.toString())
                .setParameter("credentialId", credentialId.toString())
                .setParameter("expectedVersion", expectedVersion)
                .setParameter("failedAttempts", failedAttempts)
                .setParameter("blockedUntil", blockedUntil == null ? null : Timestamp.from(blockedUntil))
                .executeUpdate();
        return changed == 1;
    }
}
