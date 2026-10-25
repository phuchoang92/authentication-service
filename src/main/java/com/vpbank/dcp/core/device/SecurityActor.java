package com.vpbank.dcp.core.device;

import java.util.Objects;

public record SecurityActor(SecurityActorType type, String id) {
    public SecurityActor {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(id, "id");
        if (id.isBlank() || id.length() > 128) {
            throw new IllegalArgumentException("Security actor is invalid");
        }
    }
}
