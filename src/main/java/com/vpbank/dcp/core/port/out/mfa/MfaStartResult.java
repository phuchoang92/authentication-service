package com.vpbank.dcp.core.port.out.mfa;

import java.time.Instant;
import java.util.Objects;

public sealed interface MfaStartResult {

    record Started(String mfaTransactionId, Instant expiresAt) implements MfaStartResult {
        public Started {
            Objects.requireNonNull(expiresAt, "expiresAt");
            if (mfaTransactionId == null || !mfaTransactionId.matches("[A-Za-z0-9_-]{22,64}")) {
                throw new InvalidMfaTransactionException();
            }
        }
    }

    /** The customer has no FACE enrolment the MFA service can use. Recovery is at a branch. */
    record NoUsableFactor() implements MfaStartResult { }
}
