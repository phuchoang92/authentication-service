package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

public final class InvalidKeycloakClientConfigurationException extends RuntimeException {

    public InvalidKeycloakClientConfigurationException() {
        super("Invalid Keycloak client configuration");
    }

    public InvalidKeycloakClientConfigurationException(Throwable cause) {
        super("Invalid Keycloak client configuration", cause);
    }
}
