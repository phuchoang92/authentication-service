package com.vpbank.dcp.core.port.out.mfa;

/** A transaction value that cannot be a well-formed MFA identifier. */
public class InvalidMfaTransactionException extends RuntimeException {
    public InvalidMfaTransactionException() {
        super(null, null, false, false);
    }
}
