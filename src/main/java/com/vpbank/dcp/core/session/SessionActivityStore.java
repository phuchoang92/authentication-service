package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Valkey view of ACTIVE sessions for idle sliding. Methods throw
 * {@link SessionActivityUnavailableException} when Valkey cannot answer, or when it is unknown
 * whether a write applied.
 */
public interface SessionActivityStore {

    Optional<UUID> currentGeneration();

    /** Empty when missing, expired, not ACTIVE or not exactly decodable. */
    Optional<LiveSession> find(SessionTokenLookup lookup);

    /**
     * Sets the idle deadline and its TTL only if {@code sessionVersion} still equals
     * {@code expectedVersion}, then increments it. False when another write or a delete won.
     */
    boolean slideIdle(SessionTokenLookup lookup, long expectedVersion, Instant idleExpiresAt);
}
