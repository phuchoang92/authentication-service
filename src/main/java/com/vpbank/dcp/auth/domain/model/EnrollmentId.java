package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;
import java.util.UUID;

/** Primary key of a TRUSTED_DEVICE_ENROLLMENT row; also the MFA {@code authOperationId}. */
public record EnrollmentId(UUID value) {
    public EnrollmentId {
        Objects.requireNonNull(value, "value");
    }

    public static EnrollmentId random() {
        return new EnrollmentId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
