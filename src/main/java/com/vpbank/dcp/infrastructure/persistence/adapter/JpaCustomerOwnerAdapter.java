package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerOwnerDecision;
import com.vpbank.dcp.core.domain.customer.CustomerOwnerPolicy;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerAcceptance;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.port.out.customer.InvalidCustomerOwnerCommandException;
import com.vpbank.dcp.infrastructure.persistence.mapper.CustomerOwnerPersistenceMapper;
import com.vpbank.dcp.infrastructure.persistence.projection.CustomerOwnerView;
import com.vpbank.dcp.infrastructure.persistence.projection.IdentityLinkView;
import com.vpbank.dcp.infrastructure.persistence.repository.CustomerOwnerPersistenceRepository;
import java.util.Objects;
import java.util.UUID;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

/** Short subject-first SQL transaction; no Customer or Keycloak call is made inside it. */
@Repository
public class JpaCustomerOwnerAdapter implements CustomerOwnerRepository {

    private final CustomerOwnerPersistenceRepository repository;
    private final TransactionTemplate transactions;
    private final CustomerOwnerPolicy policy = new CustomerOwnerPolicy();

    public JpaCustomerOwnerAdapter(CustomerOwnerPersistenceRepository repository,
                                 TransactionTemplate transactions) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.transactions = Objects.requireNonNull(transactions, "transactions");
    }

    @Override
    public CustomerOwnerAcceptance accept(UUID operationId, String appId,
                                          VerifiedProviderIdentity identity,
                                          CustomerAuthenticationState snapshot,
                                          String policyVersion) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(snapshot, "snapshot");
        if (appId == null || appId.isBlank() || appId.length() > 64
                || policyVersion == null || policyVersion.isBlank()
                || policyVersion.length() > 64) {
            throw new InvalidCustomerOwnerCommandException();
        }
        if (!snapshot.status().allowsLogin()) {
            return new CustomerOwnerAcceptance.Rejected();
        }
        try {
            return Objects.requireNonNull(transactions.execute(status -> {
                CustomerOwnerAcceptance result = acceptInTransaction(operationId, appId,
                        identity, snapshot, policyVersion);
                if (!(result instanceof CustomerOwnerAcceptance.Accepted)) {
                    status.setRollbackOnly();
                }
                return result;
            }));
        } catch (DataIntegrityViolationException failure) {
            if (isOwnerUniquenessConflict(failure)) {
                return new CustomerOwnerAcceptance.Conflict();
            }
            throw failure;
        }
    }

    private CustomerOwnerAcceptance acceptInTransaction(UUID operationId, String appId,
                                                          VerifiedProviderIdentity identity,
                                                          CustomerAuthenticationState snapshot,
                                                          String policyVersion) {
        UUID journeyId = repository.journeyId(operationId);
        if (journeyId == null) {
            return new CustomerOwnerAcceptance.NotClaimable();
        }
        CustomerOwnerView current = repository.lockSubject(snapshot.customerId());
        UUID subjectId = current == null ? UUID.randomUUID() : current.id();
        CustomerAuthenticationState persisted = current == null ? null
                : CustomerOwnerPersistenceMapper.toDomain(current);
        if (current != null) {
            CustomerOwnerDecision decision = policy.decide(persisted, snapshot);
            if (decision == CustomerOwnerDecision.CONFLICT) {
                return new CustomerOwnerAcceptance.Conflict();
            }
            if (decision == CustomerOwnerDecision.RECONCILIATION_REQUIRED) {
                return new CustomerOwnerAcceptance.ReconciliationRequired();
            }
        } else {
            repository.insertSubject(subjectId, snapshot, policyVersion);
        }

        IdentityLinkView linkedIdentity = repository.lockIdentity(subjectId, identity);
        if (linkedIdentity != null && !identity.subject().equals(linkedIdentity.providerSubject())) {
            return new CustomerOwnerAcceptance.Conflict();
        }
        String identityStatus = linkedIdentity == null ? null : linkedIdentity.status();
        if (identityStatus != null && !"ACTIVE".equals(identityStatus)) {
            return new CustomerOwnerAcceptance.Rejected();
        }
        String appStatus = repository.appStatus(subjectId, appId);
        if (appStatus != null && !"ACTIVE".equals(appStatus)) {
            return new CustomerOwnerAcceptance.Rejected();
        }
        if (repository.subjectGuardDenies(subjectId)) {
            return new CustomerOwnerAcceptance.Rejected();
        }
        if (identityStatus == null) {
            repository.insertIdentity(subjectId, identity);
        }
        if (appStatus == null) {
            repository.insertApp(subjectId, appId);
        }
        if (current != null && (snapshot.statusVersion() > persisted.statusVersion()
                || snapshot.checkedAt().isAfter(persisted.checkedAt()))) {
            repository.updateSnapshot(subjectId, snapshot);
        }
        if (repository.attachJourney(journeyId, subjectId, appId) != 1
                || repository.confirmOperation(operationId, journeyId, subjectId, appId) != 1) {
            return new CustomerOwnerAcceptance.NotClaimable();
        }
        return new CustomerOwnerAcceptance.Accepted(subjectId);
    }

    private boolean isOwnerUniquenessConflict(DataIntegrityViolationException failure) {
        if (!(failure.getCause() instanceof ConstraintViolationException constraint)
                || constraint.getSQLException().getErrorCode() != 1062) {
            return false;
        }
        String name = constraint.getConstraintName();
        return "auth_customer.uq_subject_customer".equals(name)
                || "auth_identity_link.uq_identity_provider".equals(name)
                || "auth_identity_link.uq_identity_subject_issuer".equals(name);
    }
}
