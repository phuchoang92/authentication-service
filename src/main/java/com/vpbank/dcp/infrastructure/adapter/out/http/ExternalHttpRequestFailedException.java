package com.vpbank.dcp.infrastructure.adapter.out.http;

public final class ExternalHttpRequestFailedException extends RuntimeException {

    public ExternalHttpRequestFailedException() {
        super("External HTTP request failed");
    }

    public ExternalHttpRequestFailedException(Throwable cause) {
        super("External HTTP request failed", cause);
    }
}
