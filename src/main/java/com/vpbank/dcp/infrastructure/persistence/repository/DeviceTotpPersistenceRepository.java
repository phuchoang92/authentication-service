package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.core.port.out.totp.CheckDeviceTotp;
import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Objects;
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

}
