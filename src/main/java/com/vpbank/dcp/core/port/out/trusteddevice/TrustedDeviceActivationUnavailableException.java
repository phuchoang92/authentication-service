package com.vpbank.dcp.core.port.out.trusteddevice;

/** The trust could not be committed or its outcome is unknown. */
public class TrustedDeviceActivationUnavailableException extends RuntimeException {
    public TrustedDeviceActivationUnavailableException(Throwable cause) {
        super(null, cause, false, false);
    }
}
