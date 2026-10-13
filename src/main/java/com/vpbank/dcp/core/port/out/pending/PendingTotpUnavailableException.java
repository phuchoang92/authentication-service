package com.vpbank.dcp.core.port.out.pending;

public final class PendingTotpUnavailableException extends RuntimeException {
    public PendingTotpUnavailableException() {
        super("Pending TOTP login authority is unavailable");
    }
}
