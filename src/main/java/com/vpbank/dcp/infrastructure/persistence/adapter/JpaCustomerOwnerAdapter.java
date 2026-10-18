package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerOwnerDecision;
import com.vpbank.dcp.core.domain.customer.CustomerOwnerPolicy;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerAcceptance;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerUnavailableException;
import com.vpbank.dcp.infrastructure.persistence.projection.CustomerOwnerView;
import com.vpbank.dcp.infrastructure.persistence.repository.CustomerOwnerPersistenceRepository;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionTemplate;

public final class JpaCustomerOwnerAdapter implements CustomerOwnerRepository {
    private final CustomerOwnerPersistenceRepository customers;
    private final CustomerOwnerPolicy policy;
    private final TransactionTemplate transactions;

    public JpaCustomerOwnerAdapter(CustomerOwnerPersistenceRepository customers,
                                   CustomerOwnerPolicy policy, TransactionTemplate transactions) {
        this.customers = Objects.requireNonNull(customers);
        this.policy = Objects.requireNonNull(policy);
        this.transactions = Objects.requireNonNull(transactions);
    }

    @Override
    public CustomerOwnerAcceptance accept(VerifiedProviderIdentity identity,
                                          CustomerAuthenticationState snapshot,
                                          String policyVersion) {
        Objects.requireNonNull(identity);
        Objects.requireNonNull(snapshot);
        try {
            return Objects.requireNonNull(transactions.execute(ignored ->
                    acceptLocked(identity, snapshot, policyVersion)));
        } catch (DataAccessException | TransactionException failure) {
            throw new CustomerOwnerUnavailableException(failure);
        }
    }

    private CustomerOwnerAcceptance acceptLocked(VerifiedProviderIdentity identity,
                                                 CustomerAuthenticationState snapshot,
                                                 String policyVersion) {
        if (snapshot.status() != CustomerStatus.ELIGIBLE) {
            return new CustomerOwnerAcceptance.Rejected();
        }
        Optional<CustomerOwnerView> existing = customers.lockByCustomerId(snapshot.customerNumber().value());
        if (existing.isEmpty()) {
            UUID subjectId = UUID.randomUUID();
            customers.insert(subjectId, identity, snapshot, policyVersion);
            return new CustomerOwnerAcceptance.Accepted(new SubjectId(subjectId));
        }
        CustomerOwnerView stored = existing.get();
        if (!identity.issuer().equals(stored.providerId())
                || !identity.subject().equals(stored.providerSubject())) {
            return new CustomerOwnerAcceptance.Rejected();
        }
        CustomerAuthenticationState current = new CustomerAuthenticationState(
                new CustomerNumber(stored.customerId()), status(stored.status()), stored.statusVersion(),
                stored.lastBlockVersion(), stored.checkedAt());
        if (policy.decide(current, snapshot) != CustomerOwnerDecision.ACCEPT) {
            return new CustomerOwnerAcceptance.ReconciliationRequired();
        }
        return customers.update(stored, identity, snapshot)
                ? new CustomerOwnerAcceptance.Accepted(new SubjectId(stored.id()))
                : new CustomerOwnerAcceptance.Conflict();
    }

    private CustomerStatus status(String code) {
        return switch (code) {
            case "ELIGIBLE" -> CustomerStatus.ELIGIBLE;
            case "BLOCKED" -> CustomerStatus.BLOCKED;
            case "CLOSED" -> CustomerStatus.CLOSED;
            default -> throw new UnexpectedCustomerStatusException();
        };
    }
}
