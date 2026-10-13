package com.vpbank.dcp.core.port.in.customer;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import java.util.Objects;

/** Customer's snapshot decision; local Auth guards still need a separate check. */
public sealed interface CustomerLoginEligibilityResult {

    record Eligible(CustomerAuthenticationState customer) implements CustomerLoginEligibilityResult {
        public Eligible {
            Objects.requireNonNull(customer, "customer");
        }
    }

    record Rejected() implements CustomerLoginEligibilityResult { }

    record Unavailable() implements CustomerLoginEligibilityResult { }
}
