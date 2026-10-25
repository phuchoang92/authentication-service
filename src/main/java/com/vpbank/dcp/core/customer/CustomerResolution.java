package com.vpbank.dcp.core.customer;

import java.util.Objects;

/** A missing verified identity is an expected lookup result, not provider availability. */
public sealed interface CustomerResolution {

    record Found(CustomerAuthenticationState customer) implements CustomerResolution {
        public Found {
            Objects.requireNonNull(customer, "customer");
        }
    }

    record NotFound() implements CustomerResolution {
    }
}
