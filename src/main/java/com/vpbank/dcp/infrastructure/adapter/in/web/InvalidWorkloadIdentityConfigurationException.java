package com.vpbank.dcp.infrastructure.adapter.in.web;

public final class InvalidWorkloadIdentityConfigurationException extends RuntimeException {

    public InvalidWorkloadIdentityConfigurationException() {
        super("Workload identity configuration is invalid");
    }
}
