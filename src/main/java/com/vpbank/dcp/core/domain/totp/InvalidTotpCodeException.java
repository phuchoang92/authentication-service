package com.vpbank.dcp.core.domain.totp;

public final class InvalidTotpCodeException extends IllegalArgumentException {
    public InvalidTotpCodeException() {
        super("TOTP code must contain six decimal digits");
    }
}
