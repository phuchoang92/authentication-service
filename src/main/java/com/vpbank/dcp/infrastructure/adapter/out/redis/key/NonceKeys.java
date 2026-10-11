package com.vpbank.dcp.infrastructure.adapter.out.redis.key;

import java.util.Objects;
import java.util.UUID;

public final class NonceKeys {

    private final AuthorityScope scope;

    public NonceKeys(AuthorityScope scope) {
        this.scope = Objects.requireNonNull(scope, "scope");
    }

    public String forFamily(UUID familyId) {
        Objects.requireNonNull(familyId, "familyId");
        return "nonce:v1:" + scope.value() + ":" + familyId;
    }
}
