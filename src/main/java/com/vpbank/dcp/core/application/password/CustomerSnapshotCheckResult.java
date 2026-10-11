package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import java.util.Objects;

/** Customer's snapshot decision; local Auth guards still need a separate check. */
public sealed interface CustomerSnapshotCheckResult {

    record Eligible(CustomerAuthenticationState customer) implements CustomerSnapshotCheckResult {
        public Eligible {
            Objects.requireNonNull(customer, "customer");
        }
    }

    record Rejected() implements CustomerSnapshotCheckResult { }

    record Unavailable() implements CustomerSnapshotCheckResult { }
}
