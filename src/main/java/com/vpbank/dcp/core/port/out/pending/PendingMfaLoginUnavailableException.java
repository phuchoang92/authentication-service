package com.vpbank.dcp.core.port.out.pending;

public final class PendingMfaLoginUnavailableException extends RuntimeException {
    public PendingMfaLoginUnavailableException() {
        super("Pending TOTP login authority is unavailable");
    }
}
