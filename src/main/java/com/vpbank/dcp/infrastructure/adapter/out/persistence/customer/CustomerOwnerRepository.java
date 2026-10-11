package com.vpbank.dcp.infrastructure.adapter.out.persistence.customer;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import jakarta.persistence.EntityManager;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Repository;

/** MySQL statements and row mapping for immutable Customer ownership. */
@Repository
class CustomerOwnerRepository {

    private final EntityManager entityManager;

    CustomerOwnerRepository(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager");
    }

    UUID journeyId(UUID operationId) {
        List<?> rows = entityManager.createNativeQuery(CustomerOwnerSql.FIND_JOURNEY)
                .setParameter("operationId", operationId.toString()).getResultList();
        return rows.isEmpty() ? null : UUID.fromString((String) exactlyOne(rows));
    }

    SubjectRow lockSubject(String customerId) {
        List<?> rows = entityManager.createNativeQuery(CustomerOwnerSql.LOCK_SUBJECT)
                .setParameter("customerId", customerId).getResultList();
        if (rows.isEmpty()) {
            return null;
        }
        Object[] values = (Object[]) exactlyOne(rows);
        return new SubjectRow(UUID.fromString((String) values[0]),
                new CustomerAuthenticationState(customerId, CustomerStatus.valueOf((String) values[4]),
                        ((Number) values[1]).longValue(), ((Number) values[2]).longValue(),
                        ((LocalDateTime) values[3]).toInstant(ZoneOffset.UTC)));
    }

    void insertSubject(UUID subjectId, CustomerAuthenticationState snapshot, String policyVersion) {
        entityManager.createNativeQuery(CustomerOwnerSql.INSERT_SUBJECT)
                .setParameter("subjectId", subjectId.toString())
                .setParameter("customerId", snapshot.customerId())
                .setParameter("statusVersion", snapshot.statusVersion())
                .setParameter("blockVersion", snapshot.lastAccessBlockVersion())
                .setParameter("checkedAt", Timestamp.from(snapshot.checkedAt()))
                .setParameter("policyVersion", policyVersion).executeUpdate();
    }

    int updateSnapshot(UUID subjectId, CustomerAuthenticationState snapshot) {
        return entityManager.createNativeQuery(CustomerOwnerSql.UPDATE_SNAPSHOT)
                .setParameter("subjectId", subjectId.toString())
                .setParameter("statusVersion", snapshot.statusVersion())
                .setParameter("blockVersion", snapshot.lastAccessBlockVersion())
                .setParameter("checkedAt", Timestamp.from(snapshot.checkedAt()))
                .executeUpdate();
    }

    String identityStatus(UUID subjectId, VerifiedProviderIdentity identity) {
        List<?> rows = entityManager.createNativeQuery(CustomerOwnerSql.LOCK_IDENTITY)
                .setParameter("subjectId", subjectId.toString())
                .setParameter("issuer", identity.issuer()).getResultList();
        if (rows.isEmpty()) {
            return null;
        }
        Object[] values = (Object[]) exactlyOne(rows);
        return identity.subject().equals(values[0]) ? (String) values[1] : "WRONG_OWNER";
    }

    void insertIdentity(UUID subjectId, VerifiedProviderIdentity identity) {
        entityManager.createNativeQuery(CustomerOwnerSql.INSERT_IDENTITY)
                .setParameter("linkId", UUID.randomUUID().toString())
                .setParameter("subjectId", subjectId.toString())
                .setParameter("issuer", identity.issuer())
                .setParameter("providerSubject", identity.subject()).executeUpdate();
    }

    String appStatus(UUID subjectId, String appId) {
        List<?> rows = entityManager.createNativeQuery(CustomerOwnerSql.LOCK_APP)
                .setParameter("subjectId", subjectId.toString())
                .setParameter("appId", appId).getResultList();
        return rows.isEmpty() ? null : (String) exactlyOne(rows);
    }

    void insertApp(UUID subjectId, String appId) {
        entityManager.createNativeQuery(CustomerOwnerSql.INSERT_APP)
                .setParameter("subjectId", subjectId.toString())
                .setParameter("appId", appId).executeUpdate();
    }

    boolean subjectGuardDenies(UUID subjectId) {
        Number count = (Number) entityManager.createNativeQuery(CustomerOwnerSql.SUBJECT_GUARD_DENIES)
                .setParameter("subjectId", subjectId.toString()).getSingleResult();
        return count.longValue() != 0;
    }

    int attachJourney(UUID journeyId, UUID subjectId, String appId) {
        return entityManager.createNativeQuery(CustomerOwnerSql.ATTACH_JOURNEY)
                .setParameter("journeyId", journeyId.toString())
                .setParameter("subjectId", subjectId.toString())
                .setParameter("appId", appId).executeUpdate();
    }

    int confirmOperation(UUID operationId, UUID journeyId, UUID subjectId, String appId) {
        return entityManager.createNativeQuery(CustomerOwnerSql.CONFIRM_OPERATION)
                .setParameter("operationId", operationId.toString())
                .setParameter("journeyId", journeyId.toString())
                .setParameter("subjectId", subjectId.toString())
                .setParameter("appId", appId).executeUpdate();
    }

    private Object exactlyOne(List<?> rows) {
        if (rows.size() != 1) {
            throw new UnexpectedCustomerOwnerUpdateException();
        }
        return rows.getFirst();
    }

    record SubjectRow(UUID id, CustomerAuthenticationState customer) { }
}
