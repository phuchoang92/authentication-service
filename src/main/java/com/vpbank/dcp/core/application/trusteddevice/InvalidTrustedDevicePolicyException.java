package com.vpbank.dcp.core.application.trusteddevice;

/** A trusted-device policy value outside its allowed range; fails application startup. */
public class InvalidTrustedDevicePolicyException extends RuntimeException {
    public InvalidTrustedDevicePolicyException() {
        super(null, null, false, false);
    }
}
