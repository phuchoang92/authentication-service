package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import java.util.UUID;

/** Owner acceptance is internal; it does not authorize session activation. */
public sealed interface CustomerAcceptanceResult {

    record Accepted(UUID subjectId, CustomerAuthenticationState customer)
            implements CustomerAcceptanceResult { }

    record Rejected() implements CustomerAcceptanceResult { }

    record Unavailable() implements CustomerAcceptanceResult { }

    record NotClaimable() implements CustomerAcceptanceResult { }
}
