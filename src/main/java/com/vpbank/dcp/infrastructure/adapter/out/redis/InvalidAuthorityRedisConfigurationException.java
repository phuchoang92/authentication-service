package com.vpbank.dcp.infrastructure.adapter.out.redis;

public final class InvalidAuthorityRedisConfigurationException extends RuntimeException {

    public InvalidAuthorityRedisConfigurationException() {
        super("Authority Redis configuration is not safe for serving");
    }

    public InvalidAuthorityRedisConfigurationException(Throwable cause) {
        super("Authority Redis configuration is not safe for serving", cause);
    }
}
