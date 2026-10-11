package com.vpbank.dcp.infrastructure.adapter.out.http;

public final class InvalidExternalHttpSettingsException extends RuntimeException {

    public InvalidExternalHttpSettingsException() {
        super("Invalid external HTTP settings");
    }
}
