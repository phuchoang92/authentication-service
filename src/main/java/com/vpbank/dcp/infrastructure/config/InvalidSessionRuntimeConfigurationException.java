package com.vpbank.dcp.infrastructure.config;

public final class InvalidSessionRuntimeConfigurationException extends RuntimeException {
    private static final String MESSAGE = "Session runtime configuration is incomplete or unsafe";

    public InvalidSessionRuntimeConfigurationException() {
        super(MESSAGE);
    }

    public InvalidSessionRuntimeConfigurationException(Throwable cause) {
        super(MESSAGE, cause);
    }
}
