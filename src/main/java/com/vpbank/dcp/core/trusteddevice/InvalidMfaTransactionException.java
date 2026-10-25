package com.vpbank.dcp.core.trusteddevice;

/** A value that cannot be part of a well-formed MFA transaction. */
public class InvalidMfaTransactionException extends RuntimeException {
    public InvalidMfaTransactionException() {
        super(null, null, false, false);
    }
}
