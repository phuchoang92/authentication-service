package com.vpbank.dcp.core.port.out.pending;

public final class InvalidPendingMfaLoginException extends RuntimeException {
    public InvalidPendingMfaLoginException() {
        super("Invalid pending TOTP login state");
    }
}
