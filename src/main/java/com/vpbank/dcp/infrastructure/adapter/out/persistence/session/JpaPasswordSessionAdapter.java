package com.vpbank.dcp.infrastructure.adapter.out.persistence.session;

import com.vpbank.dcp.core.domain.customer.CustomerFreshnessPolicy;
import com.vpbank.dcp.core.port.out.session.PasswordSessionFacts;
import com.vpbank.dcp.core.port.out.session.PasswordSessionRepository;
import com.vpbank.dcp.core.port.out.session.PrepareSessionResult;
import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;
import com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.session.EscrowedPasswordDelivery;
import com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.session.PasswordDeliveryEscrowCodec;
import com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.session.PasswordSessionPersistenceRepository;
import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Subject-first short transactions; no Redis or network call is made under SQL locks.
 */
public final class JpaPasswordSessionAdapter implements PasswordSessionRepository {
    private final PasswordSessionPersistenceRepository repository;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private final CustomerFreshnessPolicy freshness;
    private final PasswordDeliveryEscrowCodec escrow;

    public JpaPasswordSessionAdapter(PasswordSessionPersistenceRepository repository,
                                   TransactionTemplate transactions, Clock clock,
            CustomerFreshnessPolicy freshness, PasswordDeliveryEscrowCodec escrow) {
        this.repository = Objects.requireNonNull(repository);
        this.transactions = Objects.requireNonNull(transactions);
        this.clock = Objects.requireNonNull(clock);
        this.freshness = Objects.requireNonNull(freshness);
        this.escrow = Objects.requireNonNull(escrow);
    }

    @Override
    public Optional<PasswordSessionFacts> currentFacts(UUID operationId, UUID subjectId) {
        return facts(operationId, subjectId)
                .filter(facts -> clock.instant().isBefore(facts.customerStatusValidUntil()));
    }

    @Override
    public PrepareSessionResult prepare(PreparedPasswordSession candidate) {
        return Objects.requireNonNull(transactions.execute(status -> {
            PasswordSessionFacts facts = candidate.facts();
            UUID owner = repository.operationSubject(facts.operationId());
            if (!facts.subjectId().equals(owner)) {
                return new PrepareSessionResult.Rejected();
            }
            lock(facts);
            Optional<PreparedPasswordSession> existing = prepared(
                    facts.operationId(), facts(facts.operationId(), facts.subjectId())
                            .orElse(null));
            if (existing.isPresent()) {
                return new PrepareSessionResult.Existing(existing.get());
            }
            PasswordSessionFacts current = facts(facts.operationId(),
                    facts.subjectId()).orElse(null);
            if (!facts.equals(current) || !clock.instant().isBefore(facts.customerStatusValidUntil())
                    || repository.hasIntent(facts.operationId())) {
                return new PrepareSessionResult.Rejected();
            }
            repository.finalizeJourney(facts);
            repository.insertIntent(candidate);
            byte[] protectedResult = escrow.encode(new EscrowedPasswordDelivery(
                    candidate.tokenEnvelope(), candidate.receipt(), candidate.dpopNonce()));
            repository.insertEscrow(candidate, protectedResult, escrow.digest(protectedResult));
            return new PrepareSessionResult.Prepared(candidate);
        }));
    }

    @Override
    public Optional<PreparedPasswordSession> prepared(UUID operationId) {
        UUID subjectId = repository.operationSubject(operationId);
        if (subjectId == null) {
            return Optional.empty();
        }
        PasswordSessionFacts facts = currentFacts(operationId, subjectId).orElse(null);
        return prepared(operationId, facts);
    }

    @Override
    public boolean markApplied(UUID operationId, UUID intentId) {
        return Boolean.TRUE.equals(transactions.execute(status -> {
            PreparedPasswordSession candidate = prepared(operationId).orElse(null);
            if (candidate == null || !candidate.intentId().equals(intentId)) {
                return false;
            }
            lock(candidate.facts());
            String state = repository.intentState(operationId, intentId).orElse(null);
            if ("COMPLETED".equals(state)) {
                return true;
            }
            if (!"READY".equals(state)) {
                return false;
            }
            repository.markIntentApplied(operationId, intentId);
            repository.completeJourney(candidate.facts().journeyId());
            repository.completeOperation(operationId);
            return true;
        }));
    }

    private Optional<PasswordSessionFacts> facts(UUID operationId, UUID subjectId) {
        return repository.currentFacts(operationId, subjectId)
                .map(view -> view.toFacts(freshness.validUntil(view.customerCheckedAt())));
    }

    private void lock(PasswordSessionFacts facts) {
        repository.lockSubject(facts.subjectId());
        repository.lockSubjectApp(facts.subjectId(), facts.appId());
        repository.lockBinding(facts.bindingId(), facts.subjectId(), facts.appId());
        repository.lockJourney(facts.journeyId());
        repository.lockOperation(facts.operationId());
    }

    private Optional<PreparedPasswordSession> prepared(UUID operationId, PasswordSessionFacts facts) {
        if (facts == null) {
            return Optional.empty();
        }
        return repository.prepared(operationId).filter(view ->
                view.customerSecurityVersion() == facts.customerSecurityVersion()
                && view.credentialSecurityVersion() == facts.credentialSecurityVersion()
                && view.deviceSecurityVersion() == facts.deviceSecurityVersion()
                && view.requestKey().equals(facts.requestKey())
                && view.bindingId().equals(facts.bindingId())
                && view.subjectId().equals(facts.subjectId())).map(view -> {
                    EscrowedPasswordDelivery delivery = escrow.decode(
                            view.protectedResult(), view.resultDigest());
                    return new PreparedPasswordSession(facts, view.intentId(), view.sessionId(),
                            view.generation(), view.lookupVersion(), view.lookupDigest(),
                            view.candidateDigest(), delivery.tokenEnvelope(), delivery.receipt(),
                            delivery.dpopNonce(), view.deadlines(), view.deliveryDeadline());
                });
    }
}
