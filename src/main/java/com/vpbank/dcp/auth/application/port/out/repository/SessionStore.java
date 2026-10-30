package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;

import java.util.Optional;

/**
 * Online session authority (Valkey). Sessions are addressed by the token's keyed lookup, never
 * by session ID. Every method throws {@link RepositoryUnavailableException} when the store cannot
 * answer; an uncertain write is reported as unavailable, never as success.
 */
public interface SessionStore {

    /**
     * Stores a new ACTIVE session under the token's lookup; TTL = idle deadline.
     */
    void create(Session session, OpaqueToken token);

    Optional<StoredSession> findByToken(OpaqueToken token);

    Optional<StoredSession> findByLookup(SessionLookup lookup);

    /**
     * Saves a changed session only if the stored {@code sessionVersion} still equals
     * {@code changed.sessionVersion()}; returns the stored session (version + 1). Empty = stale.
     */
    Optional<Session> saveIfCurrent(SessionLookup lookup, Session changed);

    /**
     * Removes the session with one atomic delete. True when this call removed it, false when it was
     * already gone; of two racing callers exactly one gets true, which is the one-shot consumption the
     * trust flows need. No version check: nothing decided from a session depends on it being unchanged
     * when it is removed.
     */
    boolean delete(SessionLookup lookup);
}
