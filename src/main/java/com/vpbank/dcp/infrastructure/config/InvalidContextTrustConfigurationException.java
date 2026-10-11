package com.vpbank.dcp.infrastructure.config;

public final class InvalidContextTrustConfigurationException extends RuntimeException {

    public InvalidContextTrustConfigurationException(Throwable cause) {
        super("Keycloak context trust configuration is invalid", cause);
    }
}
