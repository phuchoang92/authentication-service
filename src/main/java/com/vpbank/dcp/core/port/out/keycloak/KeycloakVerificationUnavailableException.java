package com.vpbank.dcp.core.port.out.keycloak;

public final class KeycloakVerificationUnavailableException extends RuntimeException {

    public KeycloakVerificationUnavailableException() {
        super("Keycloak credential verification is unavailable");
    }

    public KeycloakVerificationUnavailableException(Throwable cause) {
        super("Keycloak credential verification is unavailable", cause);
    }
}
