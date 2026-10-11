package com.vpbank.dcp.core.port.out.session;

public final class InvalidSessionProofException extends RuntimeException {
    public InvalidSessionProofException(Throwable cause) {
        super("The session proof was rejected", cause);
    }
}
