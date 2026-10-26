package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import java.util.Objects;

/** Slice 6: the primary device, having passed MFA, asks for the one-time token the new device will scan. */
public record AuthorizeEnrollmentCommand(OpaqueToken token, EnrollmentId enrollmentId) {
    public AuthorizeEnrollmentCommand {
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(enrollmentId, "enrollmentId");
    }

    @Override
    public String toString() {
        return "AuthorizeEnrollmentCommand[enrollmentId=" + enrollmentId + ", redacted]";
    }
}
