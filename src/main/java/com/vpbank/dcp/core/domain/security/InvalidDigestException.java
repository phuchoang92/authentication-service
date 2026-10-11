package com.vpbank.dcp.core.domain.security;

public final class InvalidDigestException extends IllegalArgumentException {

    public InvalidDigestException() {
        super("Digest must contain exactly 32 bytes");
    }

    public InvalidDigestException(Throwable cause) {
        super("Digest must contain exactly 32 bytes", cause);
    }
}
