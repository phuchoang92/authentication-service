package com.vpbank.dcp.auth.domain.exception;

/** A session step was applied to a session that cannot take it: a programming error, not a business outcome. */
public final class SessionStateException extends IllegalStateException {
    public SessionStateException(String message) {
        super(message);
    }
}
