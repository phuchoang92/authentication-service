package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.core.port.out.keycloak.KeycloakVerificationUnavailableException;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerificationOutcome;
import com.vpbank.dcp.core.port.out.password.PasswordCredentialRecordResult;
import com.vpbank.dcp.core.port.out.password.PasswordDispatchResult;
import com.vpbank.dcp.core.port.out.password.PasswordOperationStore;
import com.vpbank.dcp.core.port.out.password.PasswordOperationProgress;
import java.time.Clock;
import java.util.Objects;
import java.util.UUID;

/** Claims one durable dispatch before sending a password to Keycloak. */
public final class VerifyPasswordLoginIdentityService {

    private final ReservePasswordLoginService admission;
    private final PasswordOperationStore operations;
    private final DirectGrantPasswordVerifier keycloak;
    private final ConfirmPasswordLoginOwnerService customers;
    private final Clock clock;

    public VerifyPasswordLoginIdentityService(ReservePasswordLoginService admission,
                                          PasswordOperationStore operations,
                                          DirectGrantPasswordVerifier keycloak,
                                          ConfirmPasswordLoginOwnerService customers,
                                          Clock clock) {
        this.admission = Objects.requireNonNull(admission, "admission");
        this.operations = Objects.requireNonNull(operations, "operations");
        this.keycloak = Objects.requireNonNull(keycloak, "keycloak");
        this.customers = Objects.requireNonNull(customers, "customers");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public PasswordLoginIdentityResult verifyIdentity(PasswordLoginCommand command) {
        Objects.requireNonNull(command, "command");
        PasswordLoginReservationResult reserved = admission.reserve(command);
        if (reserved instanceof PasswordLoginReservationResult.Rejected) {
            return new PasswordLoginIdentityResult.Rejected();
        }
        if (reserved instanceof PasswordLoginReservationResult.Conflict) {
            return new PasswordLoginIdentityResult.Conflict();
        }
        if (reserved instanceof PasswordLoginReservationResult.AuthorityClosed) {
            return new PasswordLoginIdentityResult.AuthorityClosed();
        }

        UUID operationId = command.operation().operationId();
        PasswordDispatchResult claim = operations.claimDispatch(operationId);
        if (claim == PasswordDispatchResult.ALREADY_CLAIMED) {
            return previouslyRecorded(command);
        }
        if (claim == PasswordDispatchResult.NOT_CLAIMABLE) {
            return new PasswordLoginIdentityResult.NotClaimable();
        }

        PasswordVerificationOutcome outcome;
        try {
            outcome = keycloak.verify(command.credential());
        } catch (KeycloakVerificationUnavailableException failure) {
            // Keycloak may have accepted the password. The committed claim forbids redispatch.
            PasswordCredentialRecordResult saved = operations.recordUncertain(operationId);
            return saved == PasswordCredentialRecordResult.NOT_RECORDABLE
                    ? new PasswordLoginIdentityResult.NotClaimable()
                    : new PasswordLoginIdentityResult.Processing();
        }

        if (outcome instanceof PasswordVerificationOutcome.Rejected) {
            PasswordCredentialRecordResult saved = operations.recordRejection(operationId);
            return saved == PasswordCredentialRecordResult.RECORDED
                    ? new PasswordLoginIdentityResult.Rejected()
                    : new PasswordLoginIdentityResult.NotClaimable();
        }
        PasswordVerificationOutcome.Verified verified = (PasswordVerificationOutcome.Verified) outcome;
        PasswordCredentialRecordResult recorded = operations.recordVerifiedIdentity(
                operationId, verified.identity());
        if (recorded == PasswordCredentialRecordResult.NOT_RECORDABLE) {
            return new PasswordLoginIdentityResult.NotClaimable();
        }
        return acceptCustomer(command, verified.identity());
    }

    private PasswordLoginIdentityResult acceptCustomer(PasswordLoginCommand command,
                                                         VerifiedProviderIdentity identity) {
        UUID operationId = command.operation().operationId();
        PasswordLoginOwnerResult customer = customers.confirmOwner(operationId, command.operation().appId(),
                identity, clock.instant());
        if (customer instanceof PasswordLoginOwnerResult.Rejected) {
            PasswordCredentialRecordResult saved = operations.recordRejection(operationId);
            return saved == PasswordCredentialRecordResult.RECORDED
                    ? new PasswordLoginIdentityResult.Rejected()
                    : new PasswordLoginIdentityResult.NotClaimable();
        }
        if (customer instanceof PasswordLoginOwnerResult.Unavailable) {
            return new PasswordLoginIdentityResult.Processing();
        }
        if (customer instanceof PasswordLoginOwnerResult.NotClaimable) {
            return new PasswordLoginIdentityResult.NotClaimable();
        }
        PasswordLoginOwnerResult.Accepted accepted = (PasswordLoginOwnerResult.Accepted) customer;
        // Device routing and current online authority remain separate required gates.
        return new PasswordLoginIdentityResult.Verified(identity,
                accepted.customer(), accepted.subjectId());
    }

    private PasswordLoginIdentityResult previouslyRecorded(PasswordLoginCommand command) {
        UUID operationId = command.operation().operationId();
        PasswordOperationProgress progress = operations.progress(operationId);
        if (progress == PasswordOperationProgress.REJECTED) {
            return new PasswordLoginIdentityResult.Rejected();
        }
        if (progress == PasswordOperationProgress.MFA_UNAVAILABLE) {
            return new PasswordLoginIdentityResult.MfaUnavailable();
        }
        if (progress == PasswordOperationProgress.MISSING
                || progress == PasswordOperationProgress.RESERVED) {
            return new PasswordLoginIdentityResult.NotClaimable();
        }
        if (progress == PasswordOperationProgress.VERIFIED) {
            return operations.verifiedIdentity(operationId)
                    .<PasswordLoginIdentityResult>map(identity -> acceptCustomer(command, identity))
                    .orElseGet(PasswordLoginIdentityResult.NotClaimable::new);
        }
        if (progress == PasswordOperationProgress.CONFIRMED
                || progress == PasswordOperationProgress.COMPLETED) {
            return operations.confirmedOwner(operationId)
                    .<PasswordLoginIdentityResult>map(owner ->
                            new PasswordLoginIdentityResult.Verified(
                                    owner.identity(), owner.customer(), owner.subjectId()))
                    .orElseGet(PasswordLoginIdentityResult.NotClaimable::new);
        }
        return new PasswordLoginIdentityResult.Processing();
    }
}
