package com.vpbank.dcp.infrastructure.adapter.out.crypto;

public final class InvalidDpopConfigurationException extends RuntimeException {
    private static final String MESSAGE = "Invalid DPoP configuration";

    public InvalidDpopConfigurationException() {
        super(MESSAGE);
    }
}
