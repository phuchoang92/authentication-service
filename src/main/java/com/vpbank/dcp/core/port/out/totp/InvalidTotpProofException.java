package com.vpbank.dcp.core.port.out.totp;

/** A TOTP proof that cannot be authenticated or bound to the current challenge. */
public final class InvalidTotpProofException extends RuntimeException {
    public InvalidTotpProofException() {
        super("TOTP proof was rejected");
    }
}
