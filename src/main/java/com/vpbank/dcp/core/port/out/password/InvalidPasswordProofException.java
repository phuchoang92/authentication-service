package com.vpbank.dcp.core.port.out.password;

public final class InvalidPasswordProofException extends RuntimeException {

    public InvalidPasswordProofException() {
        super("Password proof was invalid");
    }

    public InvalidPasswordProofException(Throwable cause) {
        super("Password proof was invalid", cause);
    }
}
