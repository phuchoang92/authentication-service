package com.vpbank.dcp.infrastructure.persistence.repository;

public final class InvalidSessionPersistenceException extends RuntimeException {
    public InvalidSessionPersistenceException() {
        super("The session could not be stored safely");
    }
}
