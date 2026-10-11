package com.vpbank.dcp.infrastructure.adapter.in.web.password;

public final class InvalidForwardPasswordRequestException extends RuntimeException {
    public InvalidForwardPasswordRequestException() {
        super("The password request was rejected");
    }

    public InvalidForwardPasswordRequestException(Throwable cause) {
        super("The password request was rejected", cause);
    }
}
