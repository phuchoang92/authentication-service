package com.vpbank.dcp.core.application.session;

import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.in.session.ActivateSessionCommand;
import com.vpbank.dcp.core.port.in.session.ActivateSessionUseCase;
import com.vpbank.dcp.core.port.in.session.SessionActivationResult;
import com.vpbank.dcp.core.port.out.session.SessionAuthority;
import com.vpbank.dcp.core.port.out.session.SessionCryptography;
import com.vpbank.dcp.core.port.out.session.SessionRepository;
import com.vpbank.dcp.core.port.out.session.PrepareSessionResult;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.session.SessionApplyResult;
import com.vpbank.dcp.core.port.out.session.SessionActivationSnapshot;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Publishes one durable candidate only after live guarded Redis apply. Recovery, preparation,
 * publication, completion and final delivery checks stay in order within this single use case.
 */
public final class ActivateSessionService implements ActivateSessionUseCase {
    private final SessionRepository store;
    private final SessionCryptography cryptography;
    private final SessionAuthority authority;
    private final Clock clock;

    public ActivateSessionService(SessionRepository store,
                                  SessionCryptography cryptography,
                                  SessionAuthority authority, Clock clock) {
        this.store = Objects.requireNonNull(store);
        this.cryptography = Objects.requireNonNull(cryptography);
        this.authority = Objects.requireNonNull(authority);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public SessionActivationResult activate(ActivateSessionCommand command) {
        Objects.requireNonNull(command, "command");
        UUID operationId = command.operationId();
        UUID subjectId = command.subjectId();
        PreparedSession candidate = store.prepared(operationId).orElse(null);
        if (candidate == null) {
            SessionActivationSnapshot snapshot = store.currentSnapshot(operationId, subjectId).orElse(null);
            if (snapshot == null || !snapshot.context().subjectId().equals(subjectId)) {
                return new SessionActivationResult.Rejected();
            }
            UUID generation = authority.currentGeneration().orElse(null);
            if (generation == null) {
                return new SessionActivationResult.Processing();
            }
            Instant now = clock.instant();
            candidate = cryptography.prepare(snapshot, generation,
                    SessionDeadlines.createdAt(now), now.plusSeconds(120));
            PrepareSessionResult prepared = store.prepare(candidate);
            if (prepared instanceof PrepareSessionResult.Rejected) {
                return new SessionActivationResult.Rejected();
            }
            candidate = prepared instanceof PrepareSessionResult.Existing(PreparedSession session)
                    ? session : ((PrepareSessionResult.Prepared) prepared).session();
        }
        if (!candidate.snapshot().context().subjectId().equals(subjectId)
                || !clock.instant().isBefore(candidate.delivery().deliveryDeadline())) {
            return new SessionActivationResult.Rejected();
        }
        SessionApplyResult applied = authority.apply(candidate);
        if (applied != SessionApplyResult.APPLIED && applied != SessionApplyResult.ALREADY_APPLIED) {
            return new SessionActivationResult.Processing();
        }
        if (!store.markApplied(operationId, candidate.candidate().intentId()) || !authority.deliverable(candidate)) {
            return new SessionActivationResult.Processing();
        }
        return new SessionActivationResult.Active(candidate);
    }
}
