package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.model.Session;

import java.util.Objects;

/** A session as read from the store, together with the lookup it was found under (needed to write it back). */
public record StoredSession(SessionLookup lookup, Session session) {
    public StoredSession {
        Objects.requireNonNull(lookup, "lookup");
        Objects.requireNonNull(session, "session");
    }
}
