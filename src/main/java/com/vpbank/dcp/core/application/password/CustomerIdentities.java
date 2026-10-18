package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.in.customer.CheckCustomerLoginEligibilityUseCase;
import com.vpbank.dcp.core.port.in.customer.CustomerLoginEligibilityResult;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerAcceptance;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerUnavailableException;
import com.vpbank.dcp.core.port.out.customer.InvalidCustomerOwnerCommandException;
import com.vpbank.dcp.core.port.out.credential.PasswordVerifier;
import com.vpbank.dcp.core.port.out.credential.PasswordVerifierUnavailableException;
import com.vpbank.dcp.core.port.out.credential.PasswordVerificationOutcome;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Turns a credential into a confirmed, immutable owner: one password attempt, then Customer
 * eligibility read outside SQL, then durable owner acceptance under SQL locks.
 */
public final class CustomerIdentities {
    private final PasswordVerifier passwords;
    private final CheckCustomerLoginEligibilityUseCase customers;
    private final CustomerOwnerRepository owners;
    private final String policyVersion;

    public CustomerIdentities(PasswordVerifier passwords,
                              CheckCustomerLoginEligibilityUseCase customers,
                              CustomerOwnerRepository owners, String policyVersion) {
        this.passwords = Objects.requireNonNull(passwords, "passwords");
        this.customers = Objects.requireNonNull(customers, "customers");
        this.owners = Objects.requireNonNull(owners, "owners");
        if (policyVersion == null || policyVersion.isBlank() || policyVersion.length() > 64) {
            throw new InvalidCustomerOwnerCommandException();
        }
        this.policyVersion = policyVersion;
    }

    public PasswordIdentityResult confirm(PasswordLoginCommand command) {
        Objects.requireNonNull(command);
        PasswordVerificationOutcome outcome;
        try {
            outcome = passwords.verify(command.credential());
        } catch (PasswordVerifierUnavailableException failure) {
            // The request may have reached the provider. Never dispatch this password again.
            return new PasswordIdentityResult.Denied(LoginDenial.UNAVAILABLE);
        }
        return switch (outcome) {
            case PasswordVerificationOutcome.Rejected() ->
                    new PasswordIdentityResult.Denied(LoginDenial.REJECTED);
            case PasswordVerificationOutcome.Verified(var identity) ->
                    readCustomer(identity, command.now());
        };
    }

    private PasswordIdentityResult readCustomer(VerifiedProviderIdentity identity, Instant now) {
        return switch (customers.checkEligibility(identity, now)) {
            case CustomerLoginEligibilityResult.Rejected() ->
                    new PasswordIdentityResult.Denied(LoginDenial.REJECTED);
            case CustomerLoginEligibilityResult.Unavailable() ->
                    new PasswordIdentityResult.Denied(LoginDenial.UNAVAILABLE);
            case CustomerLoginEligibilityResult.Eligible(var customer) ->
                    acceptOwner(identity, customer);
        };
    }

    private PasswordIdentityResult acceptOwner(VerifiedProviderIdentity identity,
                                               CustomerAuthenticationState customer) {
        CustomerOwnerAcceptance owner;
        try {
            owner = owners.accept(identity, customer, policyVersion);
        } catch (CustomerOwnerUnavailableException failure) {
            return new PasswordIdentityResult.Denied(LoginDenial.UNAVAILABLE);
        }
        return switch (owner) {
            case CustomerOwnerAcceptance.Accepted(SubjectId subject) ->
                    new PasswordIdentityResult.Verified(subject, customer);
            // A newer local block, an owner mismatch or an unclaimable record cannot be overridden
            // by this login snapshot. All four answer REJECTED today; PasswordLoginResult.Conflict
            // has no producer, see LoginDenial.
            case CustomerOwnerAcceptance.Rejected(),
                 CustomerOwnerAcceptance.ReconciliationRequired(),
                 CustomerOwnerAcceptance.Conflict(),
                 CustomerOwnerAcceptance.NotClaimable() ->
                    new PasswordIdentityResult.Denied(LoginDenial.REJECTED);
        };
    }
}
