package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.infrastructure.persistence.projection.CustomerOwnerView;
import jakarta.persistence.EntityManager;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class CustomerOwnerPersistenceRepository {
    private final EntityManager entityManager;

    public CustomerOwnerPersistenceRepository(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager);
    }

    public Optional<CustomerOwnerView> lockByCustomerId(String customerId) {
        List<?> rows = entityManager.createNativeQuery(CustomerOwnerSql.LOCK_BY_CUSTOMER_ID)
                .setParameter("customerId", customerId).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new UnexpectedCustomerOwnerStateException();
        }
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new CustomerOwnerView(UUID.fromString((String) row[0]),
                (String) row[1], (String) row[2], (String) row[3], (String) row[4],
                ((Number) row[5]).longValue(), ((Number) row[6]).longValue(),
                ((LocalDateTime) row[7]).toInstant(ZoneOffset.UTC),
                ((Number) row[8]).longValue()));
    }

    public void insert(UUID id, VerifiedProviderIdentity identity,
                       CustomerAuthenticationState customer, String policyVersion) {
        LocalDateTime checkedAt = utc(customer.checkedAt());
        int changed = entityManager.createNativeQuery(CustomerOwnerSql.INSERT_CUSTOMER)
                .setParameter("id", id.toString())
                .setParameter("customerId", customer.customerNumber().value())
                .setParameter("providerId", identity.issuer())
                .setParameter("providerSubject", identity.subject())
                .setParameter("statusVersion", customer.statusVersion())
                .setParameter("blockVersion", customer.lastAccessBlockVersion())
                .setParameter("checkedAt", checkedAt)
                .setParameter("policyVersion", policyVersion)
                .setParameter("now", checkedAt).executeUpdate();
        if (changed != 1) {
            throw new UnexpectedCustomerOwnerStateException();
        }
    }

    public boolean update(CustomerOwnerView stored, VerifiedProviderIdentity identity,
                          CustomerAuthenticationState customer) {
        LocalDateTime checkedAt = utc(customer.checkedAt());
        int changed = entityManager.createNativeQuery(CustomerOwnerSql.UPDATE_SNAPSHOT)
                .setParameter("id", stored.id().toString())
                .setParameter("expectedVersion", stored.version())
                .setParameter("providerId", identity.issuer())
                .setParameter("providerSubject", identity.subject())
                .setParameter("statusVersion", customer.statusVersion())
                .setParameter("blockVersion", customer.lastAccessBlockVersion())
                .setParameter("checkedAt", checkedAt)
                .setParameter("now", checkedAt).executeUpdate();
        if (changed > 1) {
            throw new UnexpectedCustomerOwnerStateException();
        }
        return changed == 1;
    }

    private LocalDateTime utc(java.time.Instant instant) {
        return LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
    }
}
