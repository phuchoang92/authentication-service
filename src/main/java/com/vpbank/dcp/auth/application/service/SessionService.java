package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.in.CurrentSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.ExtendSessionCommand;
import com.vpbank.dcp.auth.application.port.in.ExtendSessionResult;
import com.vpbank.dcp.auth.application.port.in.ExtendSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.LogoutCommand;
import com.vpbank.dcp.auth.application.port.in.LogoutResult;
import com.vpbank.dcp.auth.application.port.in.LogoutUseCase;
import com.vpbank.dcp.auth.application.port.in.SessionSummary;
import com.vpbank.dcp.auth.application.port.out.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.SessionStore;
import com.vpbank.dcp.auth.application.port.out.StoredSession;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * Everything that happens to a session after login: who is behind a token, extend on eligible
 * activity (flow 16), logout. Writes are compare-and-set on {@code sessionVersion}; a lost race
 * is re-read a bounded number of times with the same admission time, then reported as a conflict.
 */
@RequiredArgsConstructor
public final class SessionService implements CurrentSessionUseCase, ExtendSessionUseCase, LogoutUseCase {
    static final int EXTEND_ATTEMPTS = 3;

    @NonNull private final SessionStore sessions;
    @NonNull private final SessionPolicy policy;
    @NonNull private final Clock clock;

    @Override
    public Optional<SessionSummary> resolve(OpaqueToken token) {
        Instant now = clock.instant();
        return sessions.findByToken(token).map(StoredSession::session).filter(session -> session.isLive(now))
                .map(session -> new SessionSummary(session.id(), session.customerId(), session.deviceId(),
                        session.channel(), session.status(), session.idleExpiresAt(), session.absoluteExpiresAt()));
    }

    @Override
    public ExtendSessionResult extend(ExtendSessionCommand command) {
        SessionLookup lookup;
        try {
            lookup = new SessionLookup(command.lookupKeyVersion(), command.lookupDigest());
        } catch (IllegalArgumentException badShape) {
            return new ExtendSessionResult.Rejected();
        }
        try {
            for (int attempt = 0; attempt < EXTEND_ATTEMPTS; attempt++) {
                Instant now = clock.instant();
                // Only a full ACTIVE session is extended; a restricted one has a fixed TTL (DD 20 §3).
                Optional<Session> current = sessions.findByLookup(lookup).map(StoredSession::session)
                        .filter(session -> session.isFull(now));
                if (current.isEmpty()) {
                    return new ExtendSessionResult.Gone();
                }
                Session extended;
                try {
                    extended = current.get().extend(command.admittedAt(), now, policy);
                } catch (IllegalArgumentException outsideSkew) {
                    return new ExtendSessionResult.Rejected();
                }
                Optional<Session> saved = sessions.saveIfCurrent(lookup, extended);
                if (saved.isPresent()) {
                    return new ExtendSessionResult.Extended(saved.get().idleExpiresAt(), saved.get().absoluteExpiresAt());
                }
            }
            return new ExtendSessionResult.Conflict();
        } catch (RepositoryUnavailableException failure) {
            return new ExtendSessionResult.Unavailable();
        }
    }

    @Override
    public LogoutResult logout(LogoutCommand command) {
        OpaqueToken token = command.token();
        try {
            Optional<StoredSession> current = sessions.findByToken(token);
            if (current.isEmpty()) {
                return new LogoutResult.Ended();
            }
            // A stale delete means someone else changed or removed it; the caller's intent (no live
            // session for this token) is confirmed by the re-read.
            if (!sessions.deleteIfCurrent(current.get().lookup(), current.get().session())
                    && sessions.findByToken(token).isPresent()) {
                return new LogoutResult.Unavailable();
            }
            return new LogoutResult.Ended();
        } catch (RepositoryUnavailableException failure) {
            return new LogoutResult.Unavailable();
        }
    }
}
