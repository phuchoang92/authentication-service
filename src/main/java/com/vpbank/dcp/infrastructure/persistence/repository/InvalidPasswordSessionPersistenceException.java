package com.vpbank.dcp.infrastructure.persistence.repository;

public final class InvalidPasswordSessionPersistenceException extends RuntimeException {
    public InvalidPasswordSessionPersistenceException() {
        super("The password session could not be stored safely");
    }
}
