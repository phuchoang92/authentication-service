package com.vpbank.dcp.auth.core.customer;

import java.util.Objects;

/** The Customer service's current view of a customer, as needed for registration. */
public record CustomerProfile(String customerId, boolean eligible, String phone, boolean phoneVerified,
                              String email, boolean emailVerified) {
    public CustomerProfile {
        Objects.requireNonNull(customerId, "customerId");
    }

    @Override
    public String toString() {
        return "CustomerProfile[customerId=" + customerId + ", redacted]";
    }
}
