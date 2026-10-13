package com.vpbank.dcp.core.application.password;

public final class InvalidTotpChallengePolicyException extends RuntimeException {
    public InvalidTotpChallengePolicyException() {
        super("Invalid TOTP challenge lifetime policy");
    }
}
