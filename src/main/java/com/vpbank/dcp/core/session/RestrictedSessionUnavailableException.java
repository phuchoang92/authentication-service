package com.vpbank.dcp.core.session;

/** Valkey could not answer; never read as "no such session" or as permission. */
public class RestrictedSessionUnavailableException extends RuntimeException {
    public RestrictedSessionUnavailableException(Throwable cause) {
        super(null, cause, false, false);
    }
}
