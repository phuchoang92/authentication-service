package com.vpbank.dcp.auth.domain.exception;

/** An enrollment step was applied in the wrong state: a programming error, not a business outcome. */
public final class EnrollmentStateException extends IllegalStateException {
    public EnrollmentStateException(String message) {
        super(message);
    }
}
