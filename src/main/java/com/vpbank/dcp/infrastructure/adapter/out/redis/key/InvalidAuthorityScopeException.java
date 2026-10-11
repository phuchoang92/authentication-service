package com.vpbank.dcp.infrastructure.adapter.out.redis.key;

public final class InvalidAuthorityScopeException extends IllegalArgumentException {

    public InvalidAuthorityScopeException() {
        super("Authority scope is invalid");
    }
}
