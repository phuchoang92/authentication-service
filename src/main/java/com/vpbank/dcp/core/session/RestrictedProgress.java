package com.vpbank.dcp.core.session;

import java.util.Objects;

/**
 * How far a restricted session has advanced. {@code keyExchange} exists from KEY_EXCHANGE on,
 * {@code mfaTransactionId} only at MFA; the compact constructor enforces that pairing.
 */
public record RestrictedProgress(RestrictedSessionStep step, int verifyAttempts,
                                 KeyExchange keyExchange, String mfaTransactionId) {
    public RestrictedProgress {
        Objects.requireNonNull(step, "step");
        boolean keysExpected = step != RestrictedSessionStep.OPEN;
        boolean mfaExpected = step == RestrictedSessionStep.MFA;
        if (verifyAttempts < 0 || keysExpected != (keyExchange != null)
                || mfaExpected != (mfaTransactionId != null)) {
            throw new IllegalArgumentException("Invalid restricted session value");
        }
    }
}
