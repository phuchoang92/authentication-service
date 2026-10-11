package com.vpbank.dcp.infrastructure.adapter.out.redis.key;

import java.util.Objects;

public final class GenerationKeys {

    private final AuthorityScope scope;

    public GenerationKeys(AuthorityScope scope) {
        this.scope = Objects.requireNonNull(scope, "scope");
    }

    public String control() {
        return "authority:v1:" + scope.value() + ":control";
    }
}
