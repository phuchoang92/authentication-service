package com.vpbank.dcp.auth.application.result;

import java.time.Instant;

/** Outcome of the new device presenting the scanned token (slice 6). */
public sealed interface ClaimEnrollmentResult {
    /** Trusted and primary; the new ACTIVE session's token is inside the envelope. */
    record Trusted(String tokenEnvelope, Instant idleExpiresAt, Instant absoluteExpiresAt) implements ClaimEnrollmentResult {
        @Override
        public String toString() {
            return "Trusted[redacted]";
        }
    }

    /** Wrong token; 0 attempts left means the enrollment failed and the restricted session ended. */
    record WrongAuthorization(int attemptsLeft) implements ClaimEnrollmentResult { }

    /** The token outlived its 180 seconds: the enrollment expired and the restricted session ended. */
    record AuthorizationExpired() implements ClaimEnrollmentResult { }

    /** No request from this session, or it is not waiting for the token yet. */
    record Conflict() implements ClaimEnrollmentResult { }

    record SessionGone() implements ClaimEnrollmentResult { }

    record Unavailable() implements ClaimEnrollmentResult { }
}
