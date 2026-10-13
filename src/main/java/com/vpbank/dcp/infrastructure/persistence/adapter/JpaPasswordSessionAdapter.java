package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.vpbank.dcp.core.domain.customer.CustomerFreshnessPolicy;
import com.vpbank.dcp.core.port.out.session.SessionActivationSnapshot;
import com.vpbank.dcp.core.port.out.session.SessionActivationContext;
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
    public Optional<SessionActivationSnapshot> currentSnapshot(UUID operationId, UUID subjectId) {
        return snapshot(operationId, subjectId)
                .filter(snapshot -> clock.instant().isBefore(snapshot.customerStatus().validUntil()));
    }

    @Override
    public PrepareSessionResult prepare(PreparedSession candidate) {
        return Objects.requireNonNull(transactions.execute(status -> {
            SessionActivationSnapshot snapshot = candidate.snapshot();
            SessionActivationContext context = snapshot.context();
            UUID owner = repository.operationSubject(context.operationId());
            if (!context.subjectId().equals(owner)) {
                return new PrepareSessionResult.Rejected();
            }
            lock(snapshot);
            Optional<PreparedSession> existing = prepared(
                    context.operationId(), snapshot(context.operationId(), context.subjectId())
                            .orElse(null));
            if (existing.isPresent()) {
                return new PrepareSessionResult.Existing(existing.get());
            }
            SessionActivationSnapshot current = snapshot(context.operationId(),
                    context.subjectId()).orElse(null);
            if (!snapshot.equals(current) || !clock.instant().isBefore(snapshot.customerStatus().validUntil())
                    || sessions.hasIntent(context.operationId())) {
                return new PrepareSessionResult.Rejected();
            }
            repository.finalizeJourney(snapshot);
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
        SessionActivationSnapshot snapshot = currentSnapshot(operationId, subjectId).orElse(null);
        return prepared(operationId, snapshot);
    }

    @Override
    public boolean markApplied(UUID operationId, UUID intentId) {
        return Boolean.TRUE.equals(transactions.execute(status -> {
            PreparedSession candidate = prepared(operationId).orElse(null);
            if (candidate == null || !candidate.intentId().equals(intentId)) {
                return false;
            }
            lock(candidate.snapshot());
            String state = sessions.intentState(operationId, intentId).orElse(null);
            if ("COMPLETED".equals(state)) {
                return true;
            }
            if (!"READY".equals(state)) {
                return false;
            }
            sessions.markIntentApplied(operationId, intentId);
            repository.completeJourney(candidate.snapshot().context().journeyId());
            repository.completeOperation(operationId);
            return true;
        }));
    }

    private Optional<SessionActivationSnapshot> snapshot(UUID operationId, UUID subjectId) {
        return repository.currentSnapshot(operationId, subjectId)
                .map(view -> PasswordSessionPersistenceMapper.toSnapshot(view,
                        freshness.validUntil(view.customerCheckedAt())));
    }

    private void lock(SessionActivationSnapshot snapshot) {
        SessionActivationContext context = snapshot.context();
        repository.lockSubject(context.subjectId());
        repository.lockSubjectApp(context.subjectId(), context.appId());
        repository.lockBinding(context.bindingId(), context.subjectId(), context.appId());
        repository.lockJourney(context.journeyId());
        repository.lockOperation(context.operationId());
    }

    private Optional<PreparedSession> prepared(UUID operationId, SessionActivationSnapshot snapshot) {
        if (snapshot == null) {
            return Optional.empty();
        }
        return sessions.prepared(operationId).filter(view ->
                view.customerSecurityVersion() == snapshot.securityVersions().customerSecurityVersion()
                && view.credentialSecurityVersion() == snapshot.securityVersions().credentialSecurityVersion()
                && view.deviceSecurityVersion() == snapshot.securityVersions().deviceSecurityVersion()
                && SessionPersistenceMapper.toRequestKey(view).equals(snapshot.keys().requestKey())
                && view.bindingId().equals(snapshot.context().bindingId())
                && view.subjectId().equals(snapshot.context().subjectId())).map(view -> {
                    EscrowedSessionDelivery delivery = escrow.decode(
                            view.protectedResult(), SessionPersistenceMapper.toResultDigest(view));
                    return SessionPersistenceMapper.toPreparedSession(snapshot, view, delivery);
                });
    }
}
