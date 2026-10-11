package com.vpbank.dcp.infrastructure.config;

public final class InvalidPasswordRuntimeConfigurationException extends RuntimeException {
    public InvalidPasswordRuntimeConfigurationException() {
        super("Password runtime configuration is incomplete or unsafe");
    }

    public InvalidPasswordRuntimeConfigurationException(Throwable cause) {
        super("Password runtime configuration is incomplete or unsafe", cause);
    }
}
