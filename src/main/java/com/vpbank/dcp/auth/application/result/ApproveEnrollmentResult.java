package com.vpbank.dcp.auth.application.result;

import java.time.Instant;

/** Outcome of the primary device picking a waiting request (slice 6). */
public sealed interface ApproveEnrollmentResult {
    /** FACE + OTP is open at the MFA service; the primary device completes it, then calls authorize. */
    record MfaRequired(String mfaTransactionId, Instant expiresAt) implements ApproveEnrollmentResult { }

    record NotPrimaryDevice() implements ApproveEnrollmentResult { }

    /** Unknown request, not waiting for approval, or an approval is already in progress. */
    record Conflict() implements ApproveEnrollmentResult { }

    record NoUsableFactor() implements ApproveEnrollmentResult { }

    record SessionGone() implements ApproveEnrollmentResult { }

    record Unavailable() implements ApproveEnrollmentResult { }
}
