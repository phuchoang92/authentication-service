package com.vpbank.dcp.auth.domain.exception;

import com.vpbank.dcp.auth.domain.enums.RegistrationState;

/** A step was applied to a registration in the wrong state: a programming error, not a business outcome. */
public final class RegistrationStateException extends IllegalStateException {
    public RegistrationStateException(RegistrationState actual, RegistrationState... expected) {
        super("Registration is " + actual + ", expected " + String.join(" or ",
                java.util.Arrays.stream(expected).map(Enum::name).toList()));
    }
}
