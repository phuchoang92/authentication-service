package com.vpbank.dcp.infrastructure.adapter.out.http;

public final class InvalidPartnerHttpConfigurationException extends RuntimeException {

    public InvalidPartnerHttpConfigurationException() {
        super("Invalid partner HTTP configuration");
    }
}
