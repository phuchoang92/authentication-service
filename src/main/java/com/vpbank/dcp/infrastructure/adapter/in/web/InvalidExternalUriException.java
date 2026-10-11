package com.vpbank.dcp.infrastructure.adapter.in.web;

public final class InvalidExternalUriException extends IllegalArgumentException {

    public InvalidExternalUriException() {
        super("External URI is invalid");
    }

    public InvalidExternalUriException(Throwable cause) {
        super("External URI is invalid", cause);
    }
}
