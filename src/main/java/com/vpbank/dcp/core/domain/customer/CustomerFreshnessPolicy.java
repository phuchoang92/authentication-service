package com.vpbank.dcp.core.domain.customer;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/** Customer snapshots expire at the configured boundary, with no grace period. */
public final class CustomerFreshnessPolicy {
    private final Duration maxAge;

    public CustomerFreshnessPolicy(Duration maxAge) {
        this.maxAge = Objects.requireNonNull(maxAge);
        if (maxAge.isZero() || maxAge.isNegative()) {
            throw new IllegalArgumentException("Customer maximum age must be positive");
        }
    }

    public Instant validUntil(Instant checkedAt) {
        return Objects.requireNonNull(checkedAt).plus(maxAge);
    }

    public boolean isFresh(Instant checkedAt, Instant now) {
        return Objects.requireNonNull(now).isBefore(validUntil(checkedAt));
    }
}
