package com.vpbank.dcp.core.port.out.credential;

public final class InvalidPasswordVerificationException extends IllegalArgumentException {

    public InvalidPasswordVerificationException() {
        super("Invalid password verification input");
    }
}
