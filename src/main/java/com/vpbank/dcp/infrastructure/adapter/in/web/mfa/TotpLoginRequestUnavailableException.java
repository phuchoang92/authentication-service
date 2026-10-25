package com.vpbank.dcp.infrastructure.adapter.in.web.mfa;

public final class TotpLoginRequestUnavailableException extends RuntimeException {
    public TotpLoginRequestUnavailableException() {
        super("TOTP login authority is unavailable");
    }
}
