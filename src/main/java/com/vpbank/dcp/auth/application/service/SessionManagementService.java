package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.ExtendSessionCommand;
import com.vpbank.dcp.auth.application.command.LogoutCommand;
import com.vpbank.dcp.auth.application.port.in.CurrentSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.ExtendSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.LogoutUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.application.result.ExtendSessionResult;
import com.vpbank.dcp.auth.application.result.LogoutResult;
import com.vpbank.dcp.auth.application.result.SessionSummary;
import com.vpbank.dcp.auth.application.service.SessionService.ExtendOutcome;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * The session use cases after login: who is behind a token, extend on eligible activity (flow 16),
 * logout. Each one is a composition of {@link SessionService} actions and a mapping to its result.
 */
@RequiredArgsConstructor
public final class SessionManagementService implements CurrentSessionUseCase, ExtendSessionUseCase, LogoutUseCase {
    @NonNull private final SessionService sessionService;

    @Override
    public Optional<SessionSummary> resolve(OpaqueToken token) {
        Optional<StoredSession> liveSession = sessionService.findLive(token);

        return liveSession.map(StoredSession::session).map(session -> new SessionSummary(
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
        SessionLookup sessionLookup = new SessionLookup(command.channel(), command.sessionId());
        try {
            ExtendOutcome extendOutcome = sessionService.extend(sessionLookup, command.admittedAt());
            return switch (extendOutcome) {
                case ExtendOutcome.Extended(Session extendedSession) -> new ExtendSessionResult.Extended(
                        extendedSession.idleExpiresAt(),
                        extendedSession.absoluteExpiresAt());
                case ExtendOutcome.Gone() -> new ExtendSessionResult.Gone();
                case ExtendOutcome.Rejected() -> new ExtendSessionResult.Rejected();
                case ExtendOutcome.Conflict() -> new ExtendSessionResult.Conflict();
            };
        } catch (RepositoryUnavailableException failure) {
            return new ExtendSessionResult.Unavailable();
        }
    }

    /** Idempotent: a token without a live session is already logged out. */
    @Override
    public LogoutResult logout(LogoutCommand command) {
        try {
            Optional<StoredSession> liveSession = sessionService.findLive(command.token());
            if (liveSession.isPresent()) {
                sessionService.end(liveSession.get());
            }
            return new LogoutResult.Ended();
        } catch (RepositoryUnavailableException failure) {
            return new LogoutResult.Unavailable();
        }
    }
}
