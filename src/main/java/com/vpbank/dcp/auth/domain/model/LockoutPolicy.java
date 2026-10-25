package com.vpbank.dcp.auth.domain.model;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Escalating password lockout (decided 2026-10-25): after {@code captchaAfter} failures a CAPTCHA is
 * required; at each key of {@code temporaryLocks} the identity is locked for that duration; at
 * {@code permanentAt} failures it is locked until the bank unlocks it. Counts are consecutive
 * failures and only a successful login resets them. Values arrive validated from configuration.
 */
public record LockoutPolicy(int captchaAfter, SortedMap<Integer, Duration> temporaryLocks, int permanentAt) {
    public LockoutPolicy {
        Objects.requireNonNull(temporaryLocks, "temporaryLocks");
        temporaryLocks = new TreeMap<>(temporaryLocks);
        if (captchaAfter < 1 || permanentAt < 2 || temporaryLocks.isEmpty()
                || temporaryLocks.lastKey() >= permanentAt || temporaryLocks.firstKey() < 1
                || temporaryLocks.values().stream().anyMatch(d -> d.isNegative() || d.isZero())) {
            throw new IllegalArgumentException("Lockout policy needs 1 <= captchaAfter, positive lock durations at "
                    + "failure counts below permanentAt (>= 2)");
        }
    }

    /** The default policy: CAPTCHA after 2, 15 min at 3, 24 h at 4, permanent at 5. */
    public static LockoutPolicy standard() {
        return new LockoutPolicy(2, new TreeMap<>(Map.of(3, Duration.ofMinutes(15), 4, Duration.ofHours(24))), 5);
    }

    /** The temporary lock to apply at exactly this failure count, if any. */
    public Optional<Duration> temporaryLockAt(int failedCount) {
        return Optional.ofNullable(temporaryLocks.get(failedCount));
    }
}
