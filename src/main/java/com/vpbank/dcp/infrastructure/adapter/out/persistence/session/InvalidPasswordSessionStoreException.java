package com.vpbank.dcp.infrastructure.adapter.out.persistence.session;

public final class InvalidPasswordSessionStoreException extends RuntimeException {
    public InvalidPasswordSessionStoreException() {
        super("The password session could not be stored safely");
    }
}
