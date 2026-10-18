package com.vpbank.dcp.core.port.out.mfa;

/** A value that cannot be part of a well-formed MFA transaction. */
public class InvalidMfaTransactionException extends RuntimeException {
    public InvalidMfaTransactionException() {
        super(null, null, false, false);
    }
}
