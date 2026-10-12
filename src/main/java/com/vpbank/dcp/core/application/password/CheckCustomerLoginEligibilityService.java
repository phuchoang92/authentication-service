package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.InvalidCustomerFreshnessPolicyException;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectoryUnavailableException;
import com.vpbank.dcp.core.port.out.customer.CustomerResolution;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/** Reads Customer by verified provider identity; never infers eligibility from username. */
public final class CheckCustomerLoginEligibilityService {

    private final CustomerDirectory customers;
    private final Duration maximumAge;

    public CheckCustomerLoginEligibilityService(CustomerDirectory customers, Duration maximumAge) {
        this.customers = Objects.requireNonNull(customers, "customers");
        this.maximumAge = Objects.requireNonNull(maximumAge, "maximumAge");
        if (maximumAge.isNegative() || maximumAge.isZero()) {
            throw new InvalidCustomerFreshnessPolicyException();
        }
    }

    public CustomerLoginEligibilityResult checkEligibility(VerifiedProviderIdentity identity, Instant now) {
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(now, "now");
        CustomerResolution resolution;
        try {
            resolution = customers.resolve(identity);
        } catch (CustomerDirectoryUnavailableException failure) {
            return new CustomerLoginEligibilityResult.Unavailable();
        }
        if (resolution instanceof CustomerResolution.NotFound) {
            return new CustomerLoginEligibilityResult.Rejected();
        }

        CustomerAuthenticationState customer = ((CustomerResolution.Found) resolution).customer();
        if (!customer.status().allowsLogin()) {
            return new CustomerLoginEligibilityResult.Rejected();
        }
        if (!customer.isFreshAt(now, maximumAge)) {
            return new CustomerLoginEligibilityResult.Unavailable();
        }
        return new CustomerLoginEligibilityResult.Eligible(customer);
    }
}
