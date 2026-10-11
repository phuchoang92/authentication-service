package com.vpbank.dcp.core.port.out.keycloak;

public final class InvalidPasswordVerificationException extends IllegalArgumentException {

    public InvalidPasswordVerificationException() {
        super("Invalid password verification input");
    }
}
