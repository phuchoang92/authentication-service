package com.vpbank.dcp.infrastructure.adapter.out.redis.key;

import java.util.Objects;

public record AuthorityScope(String value) {

    public AuthorityScope {
        Objects.requireNonNull(value, "value");
        if (!value.matches("[A-Za-z0-9_-]{1,64}")) {
            throw new InvalidAuthorityScopeException();
        }
    }
}
