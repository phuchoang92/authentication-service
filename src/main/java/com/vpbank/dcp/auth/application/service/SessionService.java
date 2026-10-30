package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * The common session actions (ARCHITECTURE §6.1, slice 8): find a live, restricted or full session by
 * its token, issue a new session with its sealed token envelope, extend with a bounded compare-and-set
 * retry, consume or end a session. Flows ({@link LoginService}, {@link DeviceEnrollmentService},
 * {@link DeviceApprovalService}) and the use cases ({@link SessionManagementService}) compose these; this
 * class implements no use case itself and never calls a flow. Each action is one store read or write.
 */
@RequiredArgsConstructor
public final class SessionService {
    static final int EXTEND_ATTEMPTS = 3;

    @NonNull private final SessionStore sessionStore;
    @NonNull private final TokenEnvelopeSealer tokenEnvelopeSealer;
    @NonNull private final OpaqueTokenGenerator opaqueTokenGenerator;
    @NonNull private final Supplier<SessionId> sessionIdGenerator;
    @NonNull private final SessionPolicy sessionPolicy;
    @NonNull private final DevicePolicy devicePolicy;
    @NonNull private final Clock clock;

    /** A new session with the compact JWE the app decrypts to learn its token. */
    public record IssuedSession(Session session, String tokenEnvelope) {
        public IssuedSession {
            Objects.requireNonNull(session, "session");
            Objects.requireNonNull(tokenEnvelope, "tokenEnvelope");
        }

        @Override
        public String toString() {
            return "IssuedSession[sessionId=" + session.id() + ", redacted]";
        }
    }

    /** What an extend attempt ended with; the use case maps it to its result. */
    public sealed interface ExtendOutcome {
        record Extended(Session session) implements ExtendOutcome { }

        /** No full ACTIVE session under that lookup (unknown, expired, ended or restricted). */
        record Gone() implements ExtendOutcome { }

        /** The admission time is outside the accepted skew. */
        record Rejected() implements ExtendOutcome { }

        /** Every attempt lost its compare-and-set race. */
        record Conflict() implements ExtendOutcome { }
    }

    // ---- reads: one store read each ----

    public Optional<StoredSession> findLive(OpaqueToken token) {
        Instant now = clock.instant();
        return sessionStore.findByToken(token)
                .filter(stored -> stored.session().isLive(now));
    }

    /** A live NEED_TRUSTED_DEVICE session with a device: what the trust flows run on. */
    public Optional<StoredSession> findRestricted(OpaqueToken token) {
        return findLive(token)
                .filter(stored -> stored.session().status() == SessionStatus.NEED_TRUSTED_DEVICE)
                .filter(stored -> stored.session().deviceId() != null);
    }

    /** A live ACTIVE session with a device: what device management runs on. */
    public Optional<StoredSession> findActive(OpaqueToken token) {
        return findLive(token)
                .filter(stored -> stored.session().status() == SessionStatus.ACTIVE)
                .filter(stored -> stored.session().deviceId() != null);
    }

    // ---- issue ----

    public SessionId newSessionId() {
        return sessionIdGenerator.get();
    }

    /** A full ACTIVE session: start, token, envelope sealed to the app's key, stored. */
    public IssuedSession issueActive(SessionId sessionId, CustomerId customerId, DeviceId deviceId, Channel channel,
                                     String tokenEncryptionKey) {
        Session session = Session.start(
                sessionId,
                customerId,
                deviceId,
                channel,
                clock.instant(),
                sessionPolicy);
        return store(session, tokenEncryptionKey);
    }

    /** A restricted NEED_TRUSTED_DEVICE session with the device policy's fixed deadline (DD 20 §3). */
    public IssuedSession issueRestricted(SessionId sessionId, CustomerId customerId, DeviceId deviceId, Channel channel,
                                         String tokenEncryptionKey) {
        Session session = Session.startRestricted(
                sessionId,
                customerId,
                deviceId,
                channel,
                clock.instant(),
                devicePolicy);
        return store(session, tokenEncryptionKey);
    }

    private IssuedSession store(Session session, String tokenEncryptionKey) {
        OpaqueToken token = opaqueTokenGenerator.next(session.channel(), session.id());
        String tokenEnvelope = tokenEnvelopeSealer.seal(tokenEncryptionKey, token, session);
        sessionStore.create(session, token);
        return new IssuedSession(session, tokenEnvelope);
    }

    // ---- writes ----

    /** Compare-and-set on the stored version; empty when another writer moved the session first. */
    public Optional<Session> saveIfCurrent(StoredSession storedSession, Session changedSession) {
        return sessionStore.saveIfCurrent(storedSession.lookup(), changedSession);
    }

    /**
     * Flow 16: slide the idle deadline from the admission time. Only a full ACTIVE session is extended; a
     * lost race is re-read a bounded number of times with the same admission time.
     */
    public ExtendOutcome extend(SessionLookup sessionLookup, Instant admittedAt) {
        for (int attempt = 0; attempt < EXTEND_ATTEMPTS; attempt++) {
            Instant now = clock.instant();

            Optional<Session> currentFullSession = sessionStore.findByLookup(sessionLookup)
                    .map(StoredSession::session)
                    .filter(session -> session.isFull(now));
            if (currentFullSession.isEmpty()) {
                return new ExtendOutcome.Gone();
            }

            Session extendedSession;
            try {
                extendedSession = currentFullSession.get().extend(admittedAt, now, sessionPolicy);
            } catch (IllegalArgumentException outsideSkew) {
                return new ExtendOutcome.Rejected();
            }

            Optional<Session> savedSession = sessionStore.saveIfCurrent(sessionLookup, extendedSession);
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
    public boolean consume(StoredSession storedSession) {
        return sessionStore.delete(storedSession.lookup());
    }

    /** Remove the session; nothing to decide from the answer (logout, failed enrollment). */
    public void end(StoredSession storedSession) {
        sessionStore.delete(storedSession.lookup());
    }
}
