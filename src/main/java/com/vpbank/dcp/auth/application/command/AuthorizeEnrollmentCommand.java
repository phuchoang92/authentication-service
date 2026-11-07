package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import lombok.NonNull;

/** Slice 6: the primary device, having passed MFA, asks for the one-time token the new device will scan. */
public record AuthorizeEnrollmentCommand(@NonNull AdmittedSession admitted, @NonNull EnrollmentId enrollmentId) {
    @Override
    public String toString() {
        return "AuthorizeEnrollmentCommand[enrollmentId=" + enrollmentId + ", redacted]";
    }
}
