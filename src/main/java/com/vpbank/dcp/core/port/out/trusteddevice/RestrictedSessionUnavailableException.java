package com.vpbank.dcp.core.port.out.trusteddevice;

/** Valkey could not answer; never read as "no such session" or as permission. */
public class RestrictedSessionUnavailableException extends RuntimeException {
    public RestrictedSessionUnavailableException(Throwable cause) {
        super(null, cause, false, false);
    }
}
