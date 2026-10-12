package com.vpbank.dcp.infrastructure.adapter.out.redis.key;

import java.util.Objects;

/** One marker per isolated integration Redis namespace. */
public final class RuntimeKeys {

    private final AuthorityScope scope;

    public RuntimeKeys(AuthorityScope scope) {
        this.scope = Objects.requireNonNull(scope);
    }

    public String marker() {
        return "auth-runtime:v1:" + scope.value();
    }
}
