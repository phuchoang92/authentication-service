package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import java.util.Objects;

/** Slice 6: the primary device picks a waiting request; Auth opens the FACE + OTP transaction for it. */
public record ApproveEnrollmentCommand(OpaqueToken token, EnrollmentId enrollmentId) {
    public ApproveEnrollmentCommand {
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(enrollmentId, "enrollmentId");
    }

    @Override
    public String toString() {
        return "ApproveEnrollmentCommand[enrollmentId=" + enrollmentId + ", redacted]";
    }
}
