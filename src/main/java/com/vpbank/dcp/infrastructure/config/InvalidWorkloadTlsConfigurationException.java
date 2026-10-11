package com.vpbank.dcp.infrastructure.config;

public final class InvalidWorkloadTlsConfigurationException extends RuntimeException {

    public InvalidWorkloadTlsConfigurationException() {
        super("Workload TLS configuration is invalid");
    }

    public InvalidWorkloadTlsConfigurationException(Throwable cause) {
        super("Workload TLS configuration is invalid", cause);
    }
}
