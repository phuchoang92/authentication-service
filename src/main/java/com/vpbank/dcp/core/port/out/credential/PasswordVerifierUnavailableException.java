package com.vpbank.dcp.core.port.out.credential;

public final class PasswordVerifierUnavailableException extends RuntimeException {

    public PasswordVerifierUnavailableException() {
        super("Keycloak credential verification is unavailable");
    }

    public PasswordVerifierUnavailableException(Throwable cause) {
        super("Keycloak credential verification is unavailable", cause);
    }
}
