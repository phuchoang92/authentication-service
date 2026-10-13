package com.vpbank.dcp.core.port.in.customer;

import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import java.time.Instant;

/** Shared Customer login policy after verified identity; local Auth guards still apply. */
public interface CheckCustomerLoginEligibilityUseCase {
    CustomerLoginEligibilityResult checkEligibility(VerifiedProviderIdentity identity, Instant now);
}
