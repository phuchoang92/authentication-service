package com.vpbank.dcp.core.trusteddevice;

import java.util.Objects;

public sealed interface VerifyTrustedDeviceResult {

    /** The key exchange is proven; elevate this transaction at the MFA service, then confirm. */
    record MfaRequired(String mfaTransactionId) implements VerifyTrustedDeviceResult {
        public MfaRequired {
            Objects.requireNonNull(mfaTransactionId);
        }
    }

    /** The answer did not match; the App may try again {@code attemptsLeft} more times. */
    record WrongChallenge(int attemptsLeft) implements VerifyTrustedDeviceResult { }

    /** The customer has no FACE enrolment: this cannot be completed in the App. */
    record NoUsableFactor() implements VerifyTrustedDeviceResult { }

    record Rejected() implements VerifyTrustedDeviceResult { }

    record Unavailable() implements VerifyTrustedDeviceResult { }
}
