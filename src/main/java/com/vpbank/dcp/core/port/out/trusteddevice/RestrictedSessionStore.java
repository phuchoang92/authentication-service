package com.vpbank.dcp.core.port.out.trusteddevice;

import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.util.Optional;
import java.util.UUID;

/**
 * Valkey holds restricted sessions; absence or uncertainty never means allow. Every advancing
 * write succeeds at most once per session, so two concurrent calls cannot both pass a step.
 * Methods throw {@link RestrictedSessionUnavailableException} when Valkey cannot answer.
 */
public interface RestrictedSessionStore {

    Optional<UUID> currentGeneration();

    /** False means nothing usable was stored, and the token must not be delivered. */
    boolean create(PreparedRestrictedSession session);

    /** Empty when missing, expired, not NEED_TRUSTED_DEVICE or not exactly decodable. */
    Optional<StoredRestrictedSession> find(SessionTokenLookup session);

    /** OPEN → KEY_EXCHANGE, once. False when init already ran or the session is gone. */
    boolean beginKeyExchange(SessionTokenLookup session, KeyExchange exchange);

    /** Counts one verify attempt and returns the new count, or -1 when the session is gone. */
    int recordVerifyAttempt(SessionTokenLookup session);

    /** KEY_EXCHANGE → MFA, once. False when verify already passed or the session is gone. */
    boolean recordMfaTransaction(SessionTokenLookup session, String mfaTransactionId);

    /** Deletes the session. True for exactly one caller: the one allowed to finish it. */
    boolean consume(SessionTokenLookup session);
}
