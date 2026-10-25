package com.vpbank.dcp.auth.core.customer;

/** The registration database did not answer; the caller reports the step as unavailable. */
public final class RegistrationStoreUnavailableException extends RuntimeException {
    public RegistrationStoreUnavailableException(Throwable cause) {
        super("Registration store is unavailable", cause);
    }
}
