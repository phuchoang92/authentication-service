package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;
import java.util.UUID;

/** Internal identifier of a session: correlation only, never a credential the app holds. */
public record SessionId(UUID value) {
    public SessionId {
        Objects.requireNonNull(value, "value");
    }

    public static SessionId random() {
        return new SessionId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
