package com.vpbank.dcp.auth.application.port.out.exception;

/** The database did not answer; the caller reports the step as unavailable. */
public final class RepositoryUnavailableException extends RuntimeException {
    public RepositoryUnavailableException(Throwable cause) {
        super("Registration repository is unavailable", cause);
    }
}
