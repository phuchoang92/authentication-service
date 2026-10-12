package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.password;

public final class UnexpectedPasswordOperationUpdateException extends RuntimeException {

    public UnexpectedPasswordOperationUpdateException() {
        super("Password operation update count was invalid");
    }
}
