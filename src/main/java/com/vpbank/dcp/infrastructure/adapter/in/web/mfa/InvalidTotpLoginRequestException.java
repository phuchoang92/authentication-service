package com.vpbank.dcp.infrastructure.adapter.in.web.mfa;

public final class InvalidTotpLoginRequestException extends RuntimeException {
    public InvalidTotpLoginRequestException() {
        super("TOTP login request is invalid");
    }
}
