package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.time.Instant;

/** Outcome of the primary device asking for the one-time token after MFA (slice 6). */
public sealed interface AuthorizeEnrollmentResult {
    /** The token the app renders as a QR; Auth keeps only its digest. */
    record Authorized(EnrollmentId enrollmentId, String authorizationToken, Instant expiresAt)
            implements AuthorizeEnrollmentResult {
        @Override
        public String toString() {
            return "Authorized[enrollmentId=" + enrollmentId + ", redacted]";
        }
    }

    record MfaPending() implements AuthorizeEnrollmentResult { }

    record MfaFailed() implements AuthorizeEnrollmentResult { }

    record MfaExpired() implements AuthorizeEnrollmentResult { }

    record Rejected() implements AuthorizeEnrollmentResult { }

    record NotPrimaryDevice() implements AuthorizeEnrollmentResult { }

    /** Unknown request, no approval in progress, or approved by another device. */
    record Conflict() implements AuthorizeEnrollmentResult { }

    record SessionGone() implements AuthorizeEnrollmentResult { }

    record Unavailable() implements AuthorizeEnrollmentResult { }
}
