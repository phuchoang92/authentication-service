package com.vpbank.dcp.infrastructure.adapter.out.redis.key;

import java.util.Objects;
import java.util.UUID;

public final class GuardKeys {

    private final AuthorityScope scope;

    public GuardKeys(AuthorityScope scope) {
        this.scope = Objects.requireNonNull(scope, "scope");
    }

    public String forSubject(UUID subjectId) {
        return prefix("subject", subjectId);
    }

    public String forDevice(UUID bindingId) {
        return prefix("device", bindingId);
    }

    public String forSession(UUID sessionId) {
        return prefix("session", sessionId);
    }

    private String prefix(String kind, UUID id) {
        Objects.requireNonNull(id, "id");
        return "guard:v1:" + scope.value() + ":" + kind + ":" + id;
    }
}
