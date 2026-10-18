package com.vpbank.dcp.infrastructure.config;

public final class InvalidLoginIntegrationConfigurationException extends RuntimeException {
    private static final String MESSAGE = "Login integration configuration is incomplete or unsafe";

    public InvalidLoginIntegrationConfigurationException() {
        super(MESSAGE);
    }

    public InvalidLoginIntegrationConfigurationException(Throwable cause) {
        super(MESSAGE, cause);
    }
}
