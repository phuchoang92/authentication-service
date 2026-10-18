package com.vpbank.dcp.core.port.out.trusteddevice;

/** The trust could not be committed or its outcome is unknown. */
public class TrustedDeviceRecordsUnavailableException extends RuntimeException {
    public TrustedDeviceRecordsUnavailableException(Throwable cause) {
        super(null, cause, false, false);
    }
}
