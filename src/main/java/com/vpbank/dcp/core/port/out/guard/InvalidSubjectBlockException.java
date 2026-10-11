package com.vpbank.dcp.core.port.out.guard;

public final class InvalidSubjectBlockException extends RuntimeException {

    public InvalidSubjectBlockException() {
        super("Subject block is invalid");
    }
}
