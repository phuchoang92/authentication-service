package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.IssueSessionCommand;
import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.NewSession;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * The common session actions (ARCHITECTURE §6.1, slice 8): find a live, restricted or full session by
 * its token, issue a new session with its sealed token envelope, extend with a bounded compare-and-set
 * retry, consume or end a session. Flows ({@link LoginService}, {@link VerifyEnrollmentService},
 * {@link ConfirmEnrollmentService}, {@link ClaimEnrollmentService}) and the use cases ({@link SessionManagementService}) compose these; this
 * class implements no use case itself and never calls a flow. Each action is one store read or write.
 */
@RequiredArgsConstructor
public final class SessionService {
    static final int EXTEND_ATTEMPTS = 3;

    @NonNull
    private final SessionStore sessionStore;
    @NonNull
    private final TokenEnvelopeSealer tokenEnvelopeSealer;
    @NonNull
    private final OpaqueTokenGenerator opaqueTokenGenerator;
    @NonNull
    private final Supplier<SessionId> sessionIdGenerator;
    @NonNull
    private final SessionPolicy sessionPolicy;
    @NonNull
    private final DevicePolicy devicePolicy;
    @NonNull
    private final Clock clock;

    /**
     * A new session with the compact JWE the app decrypts to learn its token.
     */
    public record IssuedSession(@NonNull Session session, @NonNull String tokenEnvelope) {
        @Override
        public String toString() {
            return "IssuedSession[sessionId=" + session.id() + ", redacted]";
        }
    }

    /**
     * What an extend attempt ended with; the use case maps it to its result.
     */
    public sealed interface ExtendOutcome {
        record Extended(Session session) implements ExtendOutcome {
        }

        /**
         * No full ACTIVE session under that lookup (unknown, expired, ended or restricted).
         */
        record Gone() implements ExtendOutcome {
        }

        /**
         * The admission time is outside the accepted skew.
         */
        record Rejected() implements ExtendOutcome {
        }

        /**
         * Every attempt lost its compare-and-set race.
         */
        record Conflict() implements ExtendOutcome {
        }
    }

    // ---- reads: one store read each ----

    public Optional<StoredSession> findLive(OpaqueToken token) {
        Instant now = clock.instant();
        return sessionStore.findByToken(token)
                .filter(stored -> stored.session().isLive(now));
    }

    // ---- issue ----

    public SessionId newSessionId() {
        return sessionIdGenerator.get();
    }

    /**
     * A full ACTIVE session: start, token, envelope sealed to the app's key, stored.
     */
    public IssuedSession issueActive(@NonNull IssueSessionCommand command) {
        Session session = Session.start(newSession(command), sessionPolicy);
        return store(session, command.tokenEncryptionKey());
    }

    /**
     * A restricted NEED_TRUSTED_DEVICE session with the device policy's fixed deadline (DD 20 §3).
     */
    public IssuedSession issueRestricted(@NonNull IssueSessionCommand command) {
        Session session = Session.startRestricted(newSession(command), devicePolicy);
        return store(session, command.tokenEncryptionKey());
    }

    private NewSession newSession(IssueSessionCommand command) {
        return NewSession.builder()
                .id(command.sessionId())
                .customerId(command.customerId())
                .channel(command.channel())
                .deviceId(command.deviceId())
                .startedAt(clock.instant())
                .build();
    }

    private IssuedSession store(Session session, String tokenEncryptionKey) {
        OpaqueToken token = opaqueTokenGenerator.next(session.channel(), session.id());
        String tokenEnvelope = tokenEnvelopeSealer.seal(tokenEncryptionKey, token, session);
        sessionStore.create(session, token);
        return new IssuedSession(session, tokenEnvelope);
    }

    // ---- writes ----

    /**
     * Compare-and-set on what was read; empty when another writer moved the session first.
     */
    public Optional<Session> saveIfCurrent(StoredSession storedSession, Session changedSession) {
        return sessionStore.saveIfCurrent(storedSession, changedSession);
    }

    /**
     * Flow 16: slide the idle deadline from the admission time. Only a full ACTIVE session is extended; a
     * lost race is re-read a bounded number of times with the same admission time.
     */
    public ExtendOutcome extend(SessionLookup sessionLookup, Instant admittedAt) {
        for (int attempt = 0; attempt < EXTEND_ATTEMPTS; attempt++) {
            Instant now = clock.instant();

            Optional<StoredSession> currentFullSession = sessionStore.findByLookup(sessionLookup)
                    .filter(stored -> stored.session().isFull(now));
            if (currentFullSession.isEmpty()) {
                return new ExtendOutcome.Gone();
            }

            Session extendedSession;
            try {
                extendedSession = currentFullSession.get().session().extend(admittedAt, now, sessionPolicy);
            } catch (IllegalArgumentException outsideSkew) {
                return new ExtendOutcome.Rejected();
            }

            Optional<Session> savedSession = sessionStore.saveIfCurrent(currentFullSession.get(), extendedSession);
            if (savedSession.isPresent()) {
                return new ExtendOutcome.Extended(savedSession.get());
            }
        }
        return new ExtendOutcome.Conflict();
    }

    /**
     * One-shot consumption: of two racing callers exactly one gets {@code true}, because the delete is
     * atomic. Used before a trust commit so only one confirm or claim may proceed.
     */
    public boolean consume(SessionLookup sessionLookup) {
        return sessionStore.delete(sessionLookup);
    }

    /**
     * Remove the session; nothing to decide from the answer (logout, failed enrollment).
     */
    public void end(SessionLookup sessionLookup) {
        sessionStore.delete(sessionLookup);
    }
}
