package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.util.Objects;

/** Slice 6: the primary device, having passed MFA, asks for the one-time token the new device will scan. */
public record AuthorizeEnrollmentCommand(AdmittedSession admitted, EnrollmentId enrollmentId) {
    public AuthorizeEnrollmentCommand {
        Objects.requireNonNull(admitted, "admitted");
        Objects.requireNonNull(enrollmentId, "enrollmentId");
    }

    @Override
    public String toString() {
        return "AuthorizeEnrollmentCommand[enrollmentId=" + enrollmentId + ", redacted]";
    }
}
