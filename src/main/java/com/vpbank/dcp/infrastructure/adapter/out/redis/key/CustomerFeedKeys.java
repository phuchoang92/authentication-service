package com.vpbank.dcp.infrastructure.adapter.out.redis.key;

import java.util.Objects;

public final class CustomerFeedKeys {
    private final AuthorityScope scope;

    public CustomerFeedKeys(AuthorityScope scope) {
        this.scope = Objects.requireNonNull(scope);
    }

    public String forSource(String source) {
        if (source == null || !source.matches("[A-Za-z0-9_-]{1,64}")) {
            throw new InvalidAuthorityScopeException();
        }
        return "customer-feed:v1:" + scope.value() + ":" + source;
    }
}
