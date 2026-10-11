package com.vpbank.dcp.core.domain.security;

public final class InvalidKeyIdentifierException extends IllegalArgumentException {

    public InvalidKeyIdentifierException() {
        super("Key identifier is invalid");
    }
}
