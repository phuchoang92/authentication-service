package com.vpbank.dcp.auth.application.result;

import java.time.Instant;

public sealed interface VerifyEnrollmentResult {
    /** The device proved its key; the app now elevates FACE at the MFA service with this transaction. */
    record MfaRequired(String mfaTransactionId, Instant expiresAt) implements VerifyEnrollmentResult { }

    /** Wrong answer; {@code attemptsLeft} 0 means the enrollment and the restricted session ended. */
    record WrongChallenge(int attemptsLeft) implements VerifyEnrollmentResult { }

    /** The customer has no FACE factor: the enrollment ended, the branch must help. */
    record NoUsableFactor() implements VerifyEnrollmentResult { }

    record Conflict() implements VerifyEnrollmentResult { }

    record SessionGone() implements VerifyEnrollmentResult { }

    record Unavailable() implements VerifyEnrollmentResult { }
}
