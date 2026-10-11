package com.vpbank.dcp.infrastructure.adapter.out.redis.key;

import java.util.Objects;
import java.util.UUID;

public final class ApplyReceiptKeys {

    private final AuthorityScope scope;

    public ApplyReceiptKeys(AuthorityScope scope) {
        this.scope = Objects.requireNonNull(scope, "scope");
    }

    public String forIntent(UUID intentId) {
        Objects.requireNonNull(intentId, "intentId");
        return "apply:v1:" + scope.value() + ":" + intentId;
    }
}
