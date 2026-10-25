package com.vpbank.dcp.auth.domain.model;

/** Enrollment limits (slice 5): how many wrong challenge answers one enrollment may take. */
public record EnrollmentPolicy(int maxVerifyAttempts) {
    public EnrollmentPolicy {
        if (maxVerifyAttempts < 1 || maxVerifyAttempts > 10) {
            throw new IllegalArgumentException("maxVerifyAttempts must be 1..10");
        }
    }

    public static EnrollmentPolicy standard() {
        return new EnrollmentPolicy(3);
    }
}
