package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.session;

public final class InvalidPasswordSessionPersistenceException extends RuntimeException {
    public InvalidPasswordSessionPersistenceException() {
        super("The password session could not be stored safely");
    }
}
