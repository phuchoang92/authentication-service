package com.vpbank.dcp.core.domain.session;

public final class InvalidSessionStateException extends RuntimeException {

    public InvalidSessionStateException() {
        super("Invalid banking session state");
    }
}
