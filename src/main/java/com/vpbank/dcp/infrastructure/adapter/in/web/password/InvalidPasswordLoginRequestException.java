package com.vpbank.dcp.infrastructure.adapter.in.web.password;

public final class InvalidPasswordLoginRequestException extends RuntimeException {
    public InvalidPasswordLoginRequestException() {
        super("The password request was rejected");
    }

    public InvalidPasswordLoginRequestException(Throwable cause) {
        super("The password request was rejected", cause);
    }
}
