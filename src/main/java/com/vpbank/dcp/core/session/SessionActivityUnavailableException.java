package com.vpbank.dcp.core.session;

/** Caught by {@link ExtendSessionService} and turned into {@code UNAVAILABLE}. */
public final class SessionActivityUnavailableException extends RuntimeException {
    public SessionActivityUnavailableException(Throwable cause) {
        super("Session activity state is unavailable", cause);
    }
}
