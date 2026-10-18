package com.vpbank.dcp.core.port.out.pending;

public final class InvalidPendingTokenException extends RuntimeException {
    public InvalidPendingTokenException() {
        super("Pending token is invalid");
    }
}
