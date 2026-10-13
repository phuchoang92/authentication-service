package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.in.customer.CheckCustomerLoginEligibilityUseCase;
import com.vpbank.dcp.core.port.in.customer.CustomerLoginEligibilityResult;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerAcceptance;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerUnavailableException;
import com.vpbank.dcp.core.port.out.customer.InvalidCustomerOwnerCommandException;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Reads Customer outside SQL, then durably accepts the immutable owner under SQL locks.
 */
public final class ConfirmPasswordLoginOwnerService {

    private final CheckCustomerLoginEligibilityUseCase customers;
    private final CustomerOwnerRepository owners;
    private final String policyVersion;

    public ConfirmPasswordLoginOwnerService(CheckCustomerLoginEligibilityUseCase customers,
                                            CustomerOwnerRepository owners, String policyVersion) {
        this.customers = Objects.requireNonNull(customers, "customers");
        this.owners = Objects.requireNonNull(owners, "owners");
        if (policyVersion == null || policyVersion.isBlank() || policyVersion.length() > 64) {
            throw new InvalidCustomerOwnerCommandException();
        }
        this.policyVersion = policyVersion;
    }

    public PasswordLoginOwnerResult confirmOwner(VerifiedProviderIdentity identity, Instant now) {
        CustomerLoginEligibilityResult checked = customers.checkEligibility(identity, now);
        if (checked instanceof CustomerLoginEligibilityResult.Rejected) {
            return new PasswordLoginOwnerResult.Rejected();
        }
        if (checked instanceof CustomerLoginEligibilityResult.Unavailable) {
            return new PasswordLoginOwnerResult.Unavailable();
        }
        CustomerAuthenticationState customer =
                ((CustomerLoginEligibilityResult.Eligible) checked).customer();
        CustomerOwnerAcceptance owner;
        try {
            owner = owners.accept(identity, customer, policyVersion);
        } catch (CustomerOwnerUnavailableException failure) {
            return new PasswordLoginOwnerResult.Unavailable();
        }
        if (owner instanceof CustomerOwnerAcceptance.Accepted(UUID subjectId)) {
            return new PasswordLoginOwnerResult.Accepted(subjectId, customer);
        }
        if (owner instanceof CustomerOwnerAcceptance.NotClaimable) {
            return new PasswordLoginOwnerResult.NotClaimable();
        }
        // A newer local block or owner mismatch cannot be overridden by this login snapshot.
        return new PasswordLoginOwnerResult.Rejected();
    }
}
