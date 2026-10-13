package com.vpbank.dcp.core.port.out.pending;

public final class InvalidPendingTotpLoginException extends RuntimeException {
    public InvalidPendingTotpLoginException() {
        super("Invalid pending TOTP login state");
    }
}
