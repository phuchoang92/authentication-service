package com.vpbank.dcp.infrastructure.adapter.out.totp;

public final class InvalidTotpSecretException extends RuntimeException {
    public InvalidTotpSecretException() {
        super("Device TOTP secret is invalid");
    }

    public InvalidTotpSecretException(Throwable cause) {
        super("Device TOTP secret is invalid", cause);
    }
}
