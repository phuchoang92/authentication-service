package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.model.CustomerId;
import lombok.Builder;

import java.util.Objects;

/**
 * The Customer service's current view of a customer, as needed for registration. Phone and
 * email are kept as the partner sent them, so a malformed value compares unequal instead of
 * breaking the lookup.
 */
@Builder
public record CustomerProfile(CustomerId customerId, boolean eligible, String phone, boolean phoneVerified,
                              String email, boolean emailVerified) {
    public CustomerProfile {
        Objects.requireNonNull(customerId, "customerId");
    }

    @Override
    public String toString() {
        return "CustomerProfile[customerId=" + customerId + ", redacted]";
    }
}
