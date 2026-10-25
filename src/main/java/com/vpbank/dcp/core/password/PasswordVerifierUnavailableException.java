package com.vpbank.dcp.core.password;

public final class PasswordVerifierUnavailableException extends RuntimeException {

    public PasswordVerifierUnavailableException() {
        super("Keycloak credential verification is unavailable");
    }

    public PasswordVerifierUnavailableException(Throwable cause) {
        super("Keycloak credential verification is unavailable", cause);
    }
}
