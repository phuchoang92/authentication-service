package com.vpbank.dcp.core.trusteddevice;

/** The MFA service could not answer. Never report this as a failed or pending factor. */
public class MfaUnavailableException extends RuntimeException {
    public MfaUnavailableException(Throwable cause) {
        super(null, cause, false, false);
    }

    public MfaUnavailableException() {
        super(null, null, false, false);
    }
}
