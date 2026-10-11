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
public final class CustomerAcceptanceService {

    private final CustomerSnapshotCheckService snapshots;
    private final CustomerOwnerStore owners;
    private final String policyVersion;

    public CustomerAcceptanceService(CustomerSnapshotCheckService snapshots,
                                     CustomerOwnerStore owners, String policyVersion) {
        this.snapshots = Objects.requireNonNull(snapshots, "snapshots");
        this.owners = Objects.requireNonNull(owners, "owners");
        if (policyVersion == null || policyVersion.isBlank() || policyVersion.length() > 64) {
            throw new InvalidCustomerOwnerCommandException();
        }
        this.policyVersion = policyVersion;
    }

    public CustomerAcceptanceResult accept(UUID operationId, String appId,
                                           VerifiedProviderIdentity identity, Instant now) {
        CustomerSnapshotCheckResult checked = snapshots.check(identity, now);
        if (checked instanceof CustomerSnapshotCheckResult.Rejected) {
            return new CustomerAcceptanceResult.Rejected();
        }
        if (checked instanceof CustomerSnapshotCheckResult.Unavailable) {
            return new CustomerAcceptanceResult.Unavailable();
        }
        CustomerAuthenticationState customer =
                ((CustomerSnapshotCheckResult.Eligible) checked).customer();
        CustomerOwnerAcceptance owner = owners.accept(operationId, appId, identity,
                customer, policyVersion);
        if (owner instanceof CustomerOwnerAcceptance.Accepted accepted) {
            return new CustomerAcceptanceResult.Accepted(accepted.subjectId(), customer);
        }
        if (owner instanceof CustomerOwnerAcceptance.NotClaimable) {
            return new CustomerAcceptanceResult.NotClaimable();
        }
        // A newer local block or owner mismatch cannot be overridden by this login snapshot.
        return new CustomerAcceptanceResult.Rejected();
    }
}
