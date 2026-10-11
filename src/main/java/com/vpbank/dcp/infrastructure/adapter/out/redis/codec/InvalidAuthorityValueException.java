package com.vpbank.dcp.infrastructure.adapter.out.redis.codec;

public final class InvalidAuthorityValueException extends RuntimeException {

    public InvalidAuthorityValueException() {
        super("Authority value schema is invalid");
    }

    public InvalidAuthorityValueException(Throwable cause) {
        super("Authority value schema is invalid", cause);
    }
}
