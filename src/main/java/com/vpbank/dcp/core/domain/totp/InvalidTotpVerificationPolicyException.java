package com.vpbank.dcp.core.domain.totp;

public final class InvalidTotpVerificationPolicyException extends IllegalArgumentException {

    public InvalidTotpVerificationPolicyException() {
        super("Invalid TOTP verification policy");
    }
}
