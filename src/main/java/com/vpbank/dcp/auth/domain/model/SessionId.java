package com.vpbank.dcp.auth.domain.model;

import java.util.UUID;
import lombok.NonNull;

/** Internal identifier of a session: correlation only, never a credential the app holds. */
public record SessionId(@NonNull UUID value) {

    public static SessionId random() {
        return new SessionId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
