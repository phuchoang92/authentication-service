package com.vpbank.dcp.infrastructure.persistence.repository;

public final class UnexpectedPasswordOperationUpdateException extends RuntimeException {

    public UnexpectedPasswordOperationUpdateException() {
        super("Password operation update count was invalid");
    }
}
