package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.vpbank.dcp.core.domain.customer.CustomerFreshnessPolicy;
import com.vpbank.dcp.core.port.out.session.SessionActivationFacts;
import com.vpbank.dcp.core.port.out.session.SessionRepository;
import com.vpbank.dcp.core.port.out.session.PrepareSessionResult;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.infrastructure.persistence.codec.EscrowedSessionDelivery;
import com.vpbank.dcp.infrastructure.persistence.codec.SessionDeliveryEscrowCodec;
import com.vpbank.dcp.infrastructure.persistence.mapper.PasswordSessionPersistenceMapper;
import com.vpbank.dcp.infrastructure.persistence.mapper.SessionPersistenceMapper;
import com.vpbank.dcp.infrastructure.persistence.repository.PasswordSessionPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.SessionPersistenceRepository;
import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Subject-first short transactions; no Redis or network call is made under SQL locks.
 * Both repositories, transaction control, clock/freshness and escrow codec serve this
 * single atomic password-source bridge; separating their commits would break recovery.
 */
public final class JpaPasswordSessionAdapter implements SessionRepository {
    private final PasswordSessionPersistenceRepository repository;
    private final SessionPersistenceRepository sessions;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private final CustomerFreshnessPolicy freshness;
    private final SessionDeliveryEscrowCodec escrow;

    public JpaPasswordSessionAdapter(PasswordSessionPersistenceRepository repository,
                                     SessionPersistenceRepository sessions, TransactionTemplate transactions,
                                     Clock clock, CustomerFreshnessPolicy freshness,
                                     SessionDeliveryEscrowCodec escrow) {
        this.repository = Objects.requireNonNull(repository);
        this.sessions = Objects.requireNonNull(sessions);
        this.transactions = Objects.requireNonNull(transactions);
        this.clock = Objects.requireNonNull(clock);
        this.freshness = Objects.requireNonNull(freshness);
        this.escrow = Objects.requireNonNull(escrow);
    }

    @Override
    public Optional<SessionActivationFacts> currentFacts(UUID operationId, UUID subjectId) {
        return facts(operationId, subjectId)
                .filter(facts -> clock.instant().isBefore(facts.customerStatusValidUntil()));
    }

    @Override
    public PrepareSessionResult prepare(PreparedSession candidate) {
        return Objects.requireNonNull(transactions.execute(status -> {
            SessionActivationFacts facts = candidate.facts();
            UUID owner = repository.operationSubject(facts.operationId());
            if (!facts.subjectId().equals(owner)) {
                return new PrepareSessionResult.Rejected();
            }
            lock(facts);
            Optional<PreparedSession> existing = prepared(
                    facts.operationId(), facts(facts.operationId(), facts.subjectId())
                            .orElse(null));
            if (existing.isPresent()) {
                return new PrepareSessionResult.Existing(existing.get());
            }
            SessionActivationFacts current = facts(facts.operationId(),
                    facts.subjectId()).orElse(null);
            if (!facts.equals(current) || !clock.instant().isBefore(facts.customerStatusValidUntil())
                    || sessions.hasIntent(facts.operationId())) {
                return new PrepareSessionResult.Rejected();
            }
            repository.finalizeJourney(facts);
            sessions.insertIntent(candidate);
            byte[] protectedResult = escrow.encode(new EscrowedSessionDelivery(
                    candidate.tokenEnvelope(), candidate.receipt(), candidate.dpopNonce()));
            sessions.insertEscrow(candidate, protectedResult, escrow.digest(protectedResult));
            return new PrepareSessionResult.Prepared(candidate);
        }));
    }

    @Override
    public Optional<PreparedSession> prepared(UUID operationId) {
        UUID subjectId = repository.operationSubject(operationId);
        if (subjectId == null) {
            return Optional.empty();
        }
        SessionActivationFacts facts = currentFacts(operationId, subjectId).orElse(null);
        return prepared(operationId, facts);
    }

    @Override
    public boolean markApplied(UUID operationId, UUID intentId) {
        return Boolean.TRUE.equals(transactions.execute(status -> {
            PreparedSession candidate = prepared(operationId).orElse(null);
            if (candidate == null || !candidate.intentId().equals(intentId)) {
                return false;
            }
            lock(candidate.facts());
            String state = sessions.intentState(operationId, intentId).orElse(null);
            if ("COMPLETED".equals(state)) {
                return true;
            }
            if (!"READY".equals(state)) {
                return false;
            }
            sessions.markIntentApplied(operationId, intentId);
            repository.completeJourney(candidate.facts().journeyId());
            repository.completeOperation(operationId);
            return true;
        }));
    }

    private Optional<SessionActivationFacts> facts(UUID operationId, UUID subjectId) {
        return repository.currentFacts(operationId, subjectId)
                .map(view -> PasswordSessionPersistenceMapper.toFacts(view,
                        freshness.validUntil(view.customerCheckedAt())));
    }

    private void lock(SessionActivationFacts facts) {
        repository.lockSubject(facts.subjectId());
        repository.lockSubjectApp(facts.subjectId(), facts.appId());
        repository.lockBinding(facts.bindingId(), facts.subjectId(), facts.appId());
        repository.lockJourney(facts.journeyId());
        repository.lockOperation(facts.operationId());
    }

    private Optional<PreparedSession> prepared(UUID operationId, SessionActivationFacts facts) {
        if (facts == null) {
            return Optional.empty();
        }
        return sessions.prepared(operationId).filter(view ->
                view.customerSecurityVersion() == facts.customerSecurityVersion()
                && view.credentialSecurityVersion() == facts.credentialSecurityVersion()
                && view.deviceSecurityVersion() == facts.deviceSecurityVersion()
                && SessionPersistenceMapper.toRequestKey(view).equals(facts.requestKey())
                && view.bindingId().equals(facts.bindingId())
                && view.subjectId().equals(facts.subjectId())).map(view -> {
                    EscrowedSessionDelivery delivery = escrow.decode(
                            view.protectedResult(), SessionPersistenceMapper.toResultDigest(view));
                    return SessionPersistenceMapper.toPreparedSession(facts, view, delivery);
                });
    }
}
