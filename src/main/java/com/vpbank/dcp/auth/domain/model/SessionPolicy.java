package com.vpbank.dcp.auth.domain.model;

import java.time.Duration;
import java.util.Objects;

/**
 * Session lifetimes (flow 16): idle slides on eligible activity, absolute never moves.
 * {@code maxAdmittedAtSkew} bounds how far an admission time may lie in the past or future.
 * Values arrive validated from configuration.
 */
public record SessionPolicy(Duration idle, Duration absolute, Duration maxAdmittedAtSkew) {
    public SessionPolicy {
        Objects.requireNonNull(idle, "idle");
        Objects.requireNonNull(absolute, "absolute");
        Objects.requireNonNull(maxAdmittedAtSkew, "maxAdmittedAtSkew");
        if (idle.isNegative() || idle.isZero() || absolute.compareTo(idle) < 0 || maxAdmittedAtSkew.isNegative()) {
            throw new IllegalArgumentException("Session policy needs 0 < idle <= absolute and a non-negative skew");
        }
    }
}
