package com.vpbank.dcp.auth.domain.enums;

/**
 * Steps of one registration, in order. READY and FAILED are finished: they free the
 * customer's and the username's open slot, so a new request may start.
 */
public enum RegistrationState {
    RESERVED,
    USER_CREATED,
    SMS_ACCEPTED,
    READY,
    FAILED;

    public boolean finished() {
        return this == READY || this == FAILED;
    }
}
