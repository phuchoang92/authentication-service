package com.vpbank.dcp.core.domain.totp;

import java.time.Duration;
import java.util.Objects;

/**
 * Limits online guesses across all uses of one device credential.
 */
public record TotpVerificationPolicy(int maximumFailures, Duration lockDuration) {

    public TotpVerificationPolicy {
        Objects.requireNonNull(lockDuration, "lockDuration");
        if (maximumFailures < 1 || maximumFailures > 100
                || lockDuration.isNegative() || lockDuration.isZero()
                || lockDuration.compareTo(Duration.ofDays(1)) > 0) {
            throw new InvalidTotpVerificationPolicyException();
        }
    }
}
