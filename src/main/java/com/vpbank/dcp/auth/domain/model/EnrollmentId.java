package com.vpbank.dcp.auth.domain.model;

import java.util.UUID;
import lombok.NonNull;

/** Primary key of a TRUSTED_DEVICE_ENROLLMENT row; also the MFA {@code authOperationId}. */
public record EnrollmentId(@NonNull UUID value) {

    public static EnrollmentId random() {
        return new EnrollmentId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
