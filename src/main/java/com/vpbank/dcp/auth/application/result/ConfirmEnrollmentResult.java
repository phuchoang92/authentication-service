package com.vpbank.dcp.auth.application.result;

import java.time.Instant;

public sealed interface ConfirmEnrollmentResult {
    /** Trust committed, restricted session ended, a new ACTIVE session sealed to the key sent at confirm. */
    record Trusted(String tokenEnvelope, Instant idleExpiresAt, Instant absoluteExpiresAt)
            implements ConfirmEnrollmentResult {
        @Override
        public String toString() {
            return "Trusted[redacted]";
        }
    }

    /** FACE not done yet; the restricted session stays, the app elevates and confirms again. */
    record MfaPending() implements ConfirmEnrollmentResult { }

    record MfaFailed() implements ConfirmEnrollmentResult { }

    record MfaExpired() implements ConfirmEnrollmentResult { }

    /** The MFA receipt did not verify or did not match this enrollment; nothing changed. */
    record Rejected() implements ConfirmEnrollmentResult { }

    record Conflict() implements ConfirmEnrollmentResult { }

    record SessionGone() implements ConfirmEnrollmentResult { }

    record Unavailable() implements ConfirmEnrollmentResult { }
}
