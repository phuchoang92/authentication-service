package com.vpbank.dcp.core.port.out.security;

public final class InvalidDpopProofException extends IllegalArgumentException {
    public InvalidDpopProofException(Throwable cause) {
        super("DPoP proof is invalid", cause);
    }
}
