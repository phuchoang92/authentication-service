package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.ExtendSessionCommand;
import com.vpbank.dcp.auth.application.command.LogoutCommand;
import com.vpbank.dcp.auth.application.port.in.CurrentSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.ExtendSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.LogoutUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.application.result.ExtendSessionResult;
import com.vpbank.dcp.auth.application.result.LogoutResult;
import com.vpbank.dcp.auth.application.result.SessionSummary;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Everything that happens to a session after login: who is behind a token, extend on eligible
 * activity (flow 16), logout. Writes are compare-and-set on {@code sessionVersion}; a lost race
 * is re-read a bounded number of times with the same admission time, then reported as a conflict.
 */
@RequiredArgsConstructor
public final class SessionService implements CurrentSessionUseCase, ExtendSessionUseCase, LogoutUseCase {
    static final int EXTEND_ATTEMPTS = 3;

    @NonNull private final SessionStore sessionStore;
    @NonNull private final SessionPolicy sessionPolicy;
    @NonNull private final Clock clock;

    @Override
    public Optional<SessionSummary> resolve(OpaqueToken token) {
        Instant now = clock.instant();

        Optional<Session> liveSession = sessionStore.findByToken(token)
                .map(StoredSession::session)
                .filter(session -> session.isLive(now));

        return liveSession.map(session -> new SessionSummary(
                session.id(),
                session.customerId(),
                session.deviceId(),
                session.channel(),
                session.status(),
                session.idleExpiresAt(),
                session.absoluteExpiresAt()));
    }

    @Override
    public ExtendSessionResult extend(ExtendSessionCommand command) {
        SessionLookup sessionLookup;
        try {
            sessionLookup = new SessionLookup(command.lookupKeyVersion(), command.lookupDigest());
        } catch (IllegalArgumentException badShape) {
            return new ExtendSessionResult.Rejected();
        }

        try {
            for (int attempt = 0; attempt < EXTEND_ATTEMPTS; attempt++) {
                Instant now = clock.instant();

                // Only a full ACTIVE session is extended; a restricted one has a fixed TTL (DD 20 §3).
                Optional<Session> currentFullSession = sessionStore.findByLookup(sessionLookup)
                        .map(StoredSession::session)
                        .filter(session -> session.isFull(now));
                if (currentFullSession.isEmpty()) {
                    return new ExtendSessionResult.Gone();
                }

                Session extendedSession;
                try {
                    extendedSession = currentFullSession.get().extend(command.admittedAt(), now, sessionPolicy);
                } catch (IllegalArgumentException outsideSkew) {
                    return new ExtendSessionResult.Rejected();
                }

                Optional<Session> savedSession = sessionStore.saveIfCurrent(sessionLookup, extendedSession);
                if (savedSession.isPresent()) {
                    return new ExtendSessionResult.Extended(
                            savedSession.get().idleExpiresAt(),
                            savedSession.get().absoluteExpiresAt());
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
            Optional<StoredSession> currentSession = sessionStore.findByToken(token);
            if (currentSession.isEmpty()) {
                return new LogoutResult.Ended();
            }

            boolean deleted = sessionStore.deleteIfCurrent(
                    currentSession.get().lookup(),
                    currentSession.get().session());
            if (deleted) {
                return new LogoutResult.Ended();
            }

            // A stale delete means someone else changed or removed it; the caller's intent (no live
            // session for this token) is confirmed by the re-read.
            boolean stillStored = sessionStore.findByToken(token).isPresent();
            if (stillStored) {
                return new LogoutResult.Unavailable();
            }
            return new LogoutResult.Ended();
        } catch (RepositoryUnavailableException failure) {
            return new LogoutResult.Unavailable();
        }
    }
}
