package com.vpbank.dcp.core.port.out.password;

public final class InvalidPasswordOperationException extends IllegalArgumentException {

    public InvalidPasswordOperationException() {
        super("Password operation is invalid");
    }
}
