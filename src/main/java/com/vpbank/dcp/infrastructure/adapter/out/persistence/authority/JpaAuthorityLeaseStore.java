package com.vpbank.dcp.infrastructure.adapter.out.persistence.authority;

import com.vpbank.dcp.core.port.out.authority.AuthorityLeaseChange;
import com.vpbank.dcp.core.port.out.authority.AuthorityLeaseStore;
import com.vpbank.dcp.core.port.out.authority.LeaseChangeResult;
import jakarta.persistence.EntityManager;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** A single native CAS statement, called only inside a short SQL transaction. */
@Repository
public class JpaAuthorityLeaseStore implements AuthorityLeaseStore {

    private final EntityManager entityManager;

    public JpaAuthorityLeaseStore(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager");
    }

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public LeaseChangeResult closeWithNewFence(AuthorityLeaseChange change) {
        Objects.requireNonNull(change, "change");
        int updated = entityManager.createNativeQuery(AuthorityLeaseSql.CLOSE_WITH_NEW_FENCE)
                .setParameter("bankScope", change.bankScope())
                .setParameter("expectedVersion", change.expectedVersion())
                .setParameter("expectedFence", change.expectedFence())
                .setParameter("nextFence", change.nextFence())
                .setParameter("generation", change.generation().toString())
                .setParameter("redisRunId", change.redisRunId())
                .setParameter("controllerId", change.controllerId().toString())
                .setParameter("leaseUntil", LocalDateTime.ofInstant(change.leaseUntil(), ZoneOffset.UTC))
                .executeUpdate();
        return switch (updated) {
            case 1 -> LeaseChangeResult.UPDATED;
            case 0 -> LeaseChangeResult.STALE;
            default -> throw new UnexpectedLeaseUpdateCountException();
        };
    }
}
