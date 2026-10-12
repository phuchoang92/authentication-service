package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.out.session.PasswordSessionAuthority;
import com.vpbank.dcp.core.port.out.session.PasswordSessionCryptography;
import com.vpbank.dcp.core.port.out.session.PasswordSessionRepository;
import com.vpbank.dcp.core.port.out.session.PrepareSessionResult;
import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;
import com.vpbank.dcp.core.port.out.session.SessionApplyResult;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Publishes one durable LAST_TRUSTED candidate only after live guarded Redis apply. */
public final class ActivatePasswordSessionService {
    private final PasswordSessionRepository store;
    private final PasswordSessionCryptography cryptography;
    private final PasswordSessionAuthority authority;
    private final Clock clock;

    public ActivatePasswordSessionService(PasswordSessionRepository store,
                                  PasswordSessionCryptography cryptography,
                                  PasswordSessionAuthority authority, Clock clock) {
        this.store = Objects.requireNonNull(store);
        this.cryptography = Objects.requireNonNull(cryptography);
        this.authority = Objects.requireNonNull(authority);
        this.clock = Objects.requireNonNull(clock);
    }

    public PasswordSessionActivationResult activate(UUID operationId, UUID subjectId) {
        PreparedPasswordSession candidate = store.prepared(operationId).orElse(null);
        if (candidate == null) {
            var facts = store.currentFacts(operationId, subjectId).orElse(null);
            if (facts == null || !facts.subjectId().equals(subjectId)) {
                return new PasswordSessionActivationResult.Rejected();
            }
            UUID generation = authority.currentGeneration().orElse(null);
            if (generation == null) {
                return new PasswordSessionActivationResult.Processing();
            }
            Instant now = clock.instant();
            candidate = cryptography.prepare(facts, generation,
                    SessionDeadlines.createdAt(now), now.plusSeconds(120));
            PrepareSessionResult prepared = store.prepare(candidate);
            if (prepared instanceof PrepareSessionResult.Rejected) {
                return new PasswordSessionActivationResult.Rejected();
            }
            candidate = prepared instanceof PrepareSessionResult.Existing existing
                    ? existing.session() : ((PrepareSessionResult.Prepared) prepared).session();
        }
        if (!candidate.facts().subjectId().equals(subjectId)
                || !clock.instant().isBefore(candidate.deliveryDeadline())) {
            return new PasswordSessionActivationResult.Rejected();
        }
        SessionApplyResult applied = authority.apply(candidate);
        if (applied != SessionApplyResult.APPLIED && applied != SessionApplyResult.ALREADY_APPLIED) {
            return new PasswordSessionActivationResult.Processing();
        }
        if (!store.markApplied(operationId, candidate.intentId()) || !authority.deliverable(candidate)) {
            return new PasswordSessionActivationResult.Processing();
        }
        return new PasswordSessionActivationResult.Active(candidate);
    }
}
