package com.vpbank.dcp.auth.domain.model;

import java.time.Duration;
import lombok.NonNull;

/**
 * Session lifetimes (flow 16): idle slides on eligible activity, absolute never moves.
 * {@code maxAdmittedAtSkew} bounds how far an admission time may lie in the past or future.
 * Values arrive validated from configuration.
 */
public record SessionPolicy(@NonNull Duration idle, @NonNull Duration absolute, @NonNull Duration maxAdmittedAtSkew) {
    public SessionPolicy {
        if (idle.isNegative() || idle.isZero() || absolute.compareTo(idle) < 0 || maxAdmittedAtSkew.isNegative()) {
            throw new IllegalArgumentException("Session policy needs 0 < idle <= absolute and a non-negative skew");
        }
    }
}
