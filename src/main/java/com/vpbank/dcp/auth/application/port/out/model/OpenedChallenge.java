package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.util.Objects;

/** What the device sent back inside the response JWE: the enrollment and the challenge bytes it decrypted. */
public record OpenedChallenge(EnrollmentId enrollmentId, byte[] challenge) {
    public OpenedChallenge {
        Objects.requireNonNull(enrollmentId, "enrollmentId");
        Objects.requireNonNull(challenge, "challenge");
    }

    @Override
    public String toString() {
        return "OpenedChallenge[enrollmentId=" + enrollmentId + ", redacted]";
    }
}
