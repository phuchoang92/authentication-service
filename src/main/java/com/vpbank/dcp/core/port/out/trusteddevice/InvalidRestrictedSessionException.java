package com.vpbank.dcp.core.port.out.trusteddevice;

/** A restricted-session value that cannot be valid. */
public class InvalidRestrictedSessionException extends RuntimeException {
    public InvalidRestrictedSessionException() {
        super(null, null, false, false);
    }
}
