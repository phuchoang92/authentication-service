package com.vpbank.dcp.infrastructure.adapter.out.http;

public final class ExternalHttpRequestFailedException extends RuntimeException {

    private final int statusCode;

    public ExternalHttpRequestFailedException() {
        super("External HTTP request failed");
        statusCode = -1;
    }

    public ExternalHttpRequestFailedException(Throwable cause) {
        super("External HTTP request failed", cause);
        statusCode = -1;
    }

    public ExternalHttpRequestFailedException(int statusCode) {
        super("External HTTP request failed");
        this.statusCode = statusCode;
    }

    public int statusCode() {
        return statusCode;
    }
}
