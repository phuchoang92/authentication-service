package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import lombok.NonNull;

/** Slice 6: the primary device picks a waiting request; Auth opens the FACE + OTP transaction for it. */
public record ApproveEnrollmentCommand(@NonNull AdmittedSession admitted, @NonNull EnrollmentId enrollmentId) {
    @Override
    public String toString() {
        return "ApproveEnrollmentCommand[enrollmentId=" + enrollmentId + ", redacted]";
    }
}
