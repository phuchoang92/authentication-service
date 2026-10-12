package com.vpbank.dcp.infrastructure.adapter.out.persistence.session;

import com.vpbank.dcp.core.port.out.session.PasswordSessionFacts;
import com.vpbank.dcp.core.port.out.session.PasswordSessionStore;
import com.vpbank.dcp.core.port.out.session.PrepareSessionResult;
import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Subject-first short transactions; no Redis or network call is made under SQL locks.
 */
public final class JpaPasswordSessionStore implements PasswordSessionStore {
    private final PasswordSessionRepository repository;
    private final TransactionTemplate transactions;
    private final Clock clock;

    public JpaPasswordSessionStore(PasswordSessionRepository repository,
                                   TransactionTemplate transactions, Clock clock) {
        this.repository = Objects.requireNonNull(repository);
        this.transactions = Objects.requireNonNull(transactions);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public Optional<PasswordSessionFacts> currentFacts(UUID operationId, UUID subjectId) {
        return repository.currentFacts(operationId, subjectId)
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
            repository.lock(facts);
            Optional<PreparedPasswordSession> existing = repository.prepared(
                    facts.operationId(), repository.currentFacts(facts.operationId(), facts.subjectId())
                            .orElse(null));
            if (existing.isPresent()) {
                return new PrepareSessionResult.Existing(existing.get());
            }
            PasswordSessionFacts current = repository.currentFacts(facts.operationId(),
                    facts.subjectId()).orElse(null);
            if (!facts.equals(current) || !clock.instant().isBefore(facts.customerStatusValidUntil())
                    || repository.hasIntent(facts.operationId())) {
                return new PrepareSessionResult.Rejected();
            }
            repository.insert(candidate);
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
        return repository.prepared(operationId, facts);
    }

    @Override
    public boolean markApplied(UUID operationId, UUID intentId) {
        return Boolean.TRUE.equals(transactions.execute(status -> {
            PreparedPasswordSession candidate = prepared(operationId).orElse(null);
            if (candidate == null || !candidate.intentId().equals(intentId)) {
                return false;
            }
            repository.lock(candidate.facts());
            return repository.markApplied(candidate);
        }));
    }
}
