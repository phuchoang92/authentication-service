package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerAcceptance;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerStore;
import com.vpbank.dcp.core.port.out.customer.InvalidCustomerOwnerCommandException;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Reads Customer outside SQL, then durably accepts the immutable owner under SQL locks. */
public final class ConfirmPasswordLoginOwnerService {

    private final CheckCustomerLoginEligibilityService snapshots;
    private final CustomerOwnerStore owners;
    private final String policyVersion;

    public ConfirmPasswordLoginOwnerService(CheckCustomerLoginEligibilityService snapshots,
                                     CustomerOwnerStore owners, String policyVersion) {
        this.snapshots = Objects.requireNonNull(snapshots, "snapshots");
        this.owners = Objects.requireNonNull(owners, "owners");
        if (policyVersion == null || policyVersion.isBlank() || policyVersion.length() > 64) {
            throw new InvalidCustomerOwnerCommandException();
        }
        this.policyVersion = policyVersion;
    }

    public PasswordLoginOwnerResult confirmOwner(UUID operationId, String appId,
                                           VerifiedProviderIdentity identity, Instant now) {
        CustomerLoginEligibilityResult checked = snapshots.checkEligibility(identity, now);
        if (checked instanceof CustomerLoginEligibilityResult.Rejected) {
            return new PasswordLoginOwnerResult.Rejected();
        }
        if (checked instanceof CustomerLoginEligibilityResult.Unavailable) {
            return new PasswordLoginOwnerResult.Unavailable();
        }
        CustomerAuthenticationState customer =
                ((CustomerLoginEligibilityResult.Eligible) checked).customer();
        CustomerOwnerAcceptance owner = owners.accept(operationId, appId, identity,
                customer, policyVersion);
        if (owner instanceof CustomerOwnerAcceptance.Accepted accepted) {
            return new PasswordLoginOwnerResult.Accepted(accepted.subjectId(), customer);
        }
        if (owner instanceof CustomerOwnerAcceptance.NotClaimable) {
            return new PasswordLoginOwnerResult.NotClaimable();
        }
        // A newer local block or owner mismatch cannot be overridden by this login snapshot.
        return new PasswordLoginOwnerResult.Rejected();
    }
}
