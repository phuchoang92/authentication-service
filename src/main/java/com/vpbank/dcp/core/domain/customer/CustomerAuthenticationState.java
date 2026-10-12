package com.vpbank.dcp.core.domain.customer;

import java.time.Instant;
import java.util.Objects;

/**
 * A verified Customer snapshot, not a banking-session authorization decision.
 */
public record CustomerAuthenticationState(
        String customerId,
        CustomerStatus status,
        long statusVersion,
        long lastAccessBlockVersion,
        Instant checkedAt) {

    private static final long MAX_SAFE_INTEGER = 9_007_199_254_740_991L;

    public CustomerAuthenticationState {
        if (customerId == null || !customerId.matches("[A-Za-z0-9._:-]{1,128}")
                || status == null || checkedAt == null
                || statusVersion > MAX_SAFE_INTEGER
                || lastAccessBlockVersion < 0 || lastAccessBlockVersion > statusVersion
                || (!status.allowsLogin() && lastAccessBlockVersion != statusVersion)) {
            throw new InvalidCustomerStateException();
        }
    }

    public boolean isFreshAt(Instant now, java.time.Duration maximumAge) {
        Objects.requireNonNull(now, "now");
        Objects.requireNonNull(maximumAge, "maximumAge");
        return !maximumAge.isNegative() && !maximumAge.isZero()
                && !checkedAt.isAfter(now)
                && checkedAt.plus(maximumAge).isAfter(now);
    }
}
