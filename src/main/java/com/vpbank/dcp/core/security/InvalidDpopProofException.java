package com.vpbank.dcp.core.security;

public final class InvalidDpopProofException extends IllegalArgumentException {
    public InvalidDpopProofException(Throwable cause) {
        super("DPoP proof is invalid", cause);
    }
}
