package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import lombok.NonNull;

/** What the device sent back inside the response JWE: the enrollment and the challenge bytes it decrypted. */
public record OpenedChallenge(@NonNull EnrollmentId enrollmentId, @NonNull byte[] challenge) {
    @Override
    public String toString() {
        return "OpenedChallenge[enrollmentId=" + enrollmentId + ", redacted]";
    }
}
