package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Test double with the store's contract: a session is addressed by the token's channel and session ID; a save
 * succeeds only while the store still holds the session the caller read; version + 1 on every saved change. The
 * secret is not checked here, and every record carries the same stand-in digest.
 */
final class InMemorySessionStore implements SessionStore {
    static final String ANY_DIGEST = "d".repeat(43);
    final Map<SessionLookup, Session> rows = new HashMap<>();
    boolean unavailable;
    /** When > 0, each saveIfCurrent is preceded by a concurrent bump of the stored version. */
    int concurrentBumps;

    static SessionLookup lookupOf(OpaqueToken token) {
        return new SessionLookup(token.channel(), token.sessionId());
    }

    @Override
    public void create(Session session, OpaqueToken token) {
        check();
        rows.put(lookupOf(token), session);
    }

    @Override
    public Optional<StoredSession> findByToken(OpaqueToken token) {
        return findByLookup(lookupOf(token));
    }

    @Override
    public Optional<StoredSession> findByLookup(SessionLookup lookup) {
        check();
        return Optional.ofNullable(rows.get(lookup)).map(session -> new StoredSession(lookup, session, ANY_DIGEST));
    }

    @Override
    public Optional<Session> saveIfCurrent(StoredSession current, Session changed) {
        check();
        SessionLookup lookup = current.lookup();
        if (concurrentBumps > 0 && rows.containsKey(lookup)) {
            concurrentBumps--;
            rows.put(lookup, rows.get(lookup).withSessionVersion(rows.get(lookup).sessionVersion() + 1));
        }
        if (!current.session().equals(rows.get(lookup))) {
            return Optional.empty();
        }
        Session saved = changed.withSessionVersion(current.session().sessionVersion() + 1);
        rows.put(lookup, saved);
        return Optional.of(saved);
    }

    @Override
    public boolean delete(SessionLookup lookup) {
        check();
        return rows.remove(lookup) != null;
    }

    Session only() {
        return rows.values().iterator().next();
    }

    private void check() {
        if (unavailable) {
            throw new RepositoryUnavailableException(new RuntimeException("down"));
        }
    }
}
