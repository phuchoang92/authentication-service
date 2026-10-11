package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
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
public final class PasswordCredentialCheckService {

    private final PasswordAdmissionService admission;
    private final PasswordOperationStore operations;
    private final DirectGrantPasswordVerifier keycloak;
    private final CustomerAcceptanceService customers;
    private final Clock clock;

    public PasswordCredentialCheckService(PasswordAdmissionService admission,
                                          PasswordOperationStore operations,
                                          DirectGrantPasswordVerifier keycloak,
                                          CustomerAcceptanceService customers,
                                          Clock clock) {
        this.admission = Objects.requireNonNull(admission, "admission");
        this.operations = Objects.requireNonNull(operations, "operations");
        this.keycloak = Objects.requireNonNull(keycloak, "keycloak");
        this.customers = Objects.requireNonNull(customers, "customers");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public PasswordCredentialCheckResult check(PasswordAdmissionCommand command) {
        Objects.requireNonNull(command, "command");
        PasswordAdmissionResult reserved = admission.reserve(command);
        if (reserved instanceof PasswordAdmissionResult.Rejected) {
            return new PasswordCredentialCheckResult.Rejected();
        }
        if (reserved instanceof PasswordAdmissionResult.Conflict) {
            return new PasswordCredentialCheckResult.Conflict();
        }
        if (reserved instanceof PasswordAdmissionResult.AuthorityClosed) {
            return new PasswordCredentialCheckResult.AuthorityClosed();
        }

        UUID operationId = command.operation().operationId();
        PasswordDispatchResult claim = operations.claimDispatch(operationId);
        if (claim == PasswordDispatchResult.ALREADY_CLAIMED) {
            return previouslyRecorded(command);
        }
        if (claim == PasswordDispatchResult.NOT_CLAIMABLE) {
            return new PasswordCredentialCheckResult.NotClaimable();
        }

        PasswordVerificationOutcome outcome;
        try {
            outcome = keycloak.verify(command.credential());
        } catch (KeycloakVerificationUnavailableException failure) {
            // Keycloak may have accepted the password. The committed claim forbids redispatch.
            PasswordCredentialRecordResult saved = operations.recordUncertain(operationId);
            return saved == PasswordCredentialRecordResult.NOT_RECORDABLE
                    ? new PasswordCredentialCheckResult.NotClaimable()
                    : new PasswordCredentialCheckResult.Processing();
        }

        if (outcome instanceof PasswordVerificationOutcome.Rejected) {
            PasswordCredentialRecordResult saved = operations.recordRejection(operationId);
            return saved == PasswordCredentialRecordResult.RECORDED
                    ? new PasswordCredentialCheckResult.Rejected()
                    : new PasswordCredentialCheckResult.NotClaimable();
        }
        PasswordVerificationOutcome.Verified verified = (PasswordVerificationOutcome.Verified) outcome;
        PasswordCredentialRecordResult recorded = operations.recordVerifiedIdentity(
                operationId, verified.identity());
        if (recorded == PasswordCredentialRecordResult.NOT_RECORDABLE) {
            return new PasswordCredentialCheckResult.NotClaimable();
        }
        return acceptCustomer(command, verified.identity());
    }

    private PasswordCredentialCheckResult acceptCustomer(PasswordAdmissionCommand command,
                                                         VerifiedProviderIdentity identity) {
        UUID operationId = command.operation().operationId();
        CustomerAcceptanceResult customer = customers.accept(operationId, command.operation().appId(),
                identity, clock.instant());
        if (customer instanceof CustomerAcceptanceResult.Rejected) {
            PasswordCredentialRecordResult saved = operations.recordRejection(operationId);
            return saved == PasswordCredentialRecordResult.RECORDED
                    ? new PasswordCredentialCheckResult.Rejected()
                    : new PasswordCredentialCheckResult.NotClaimable();
        }
        if (customer instanceof CustomerAcceptanceResult.Unavailable) {
            return new PasswordCredentialCheckResult.Processing();
        }
        if (customer instanceof CustomerAcceptanceResult.NotClaimable) {
            return new PasswordCredentialCheckResult.NotClaimable();
        }
        CustomerAcceptanceResult.Accepted accepted = (CustomerAcceptanceResult.Accepted) customer;
        // Device routing and current online authority remain separate required gates.
        return new PasswordCredentialCheckResult.Verified(identity,
                accepted.customer(), accepted.subjectId());
    }

    private PasswordCredentialCheckResult previouslyRecorded(PasswordAdmissionCommand command) {
        UUID operationId = command.operation().operationId();
        PasswordOperationProgress progress = operations.progress(operationId);
        if (progress == PasswordOperationProgress.REJECTED) {
            return new PasswordCredentialCheckResult.Rejected();
        }
        if (progress == PasswordOperationProgress.MFA_UNAVAILABLE) {
            return new PasswordCredentialCheckResult.MfaUnavailable();
        }
        if (progress == PasswordOperationProgress.MISSING
                || progress == PasswordOperationProgress.RESERVED) {
            return new PasswordCredentialCheckResult.NotClaimable();
        }
        if (progress == PasswordOperationProgress.VERIFIED) {
            return operations.verifiedIdentity(operationId)
                    .<PasswordCredentialCheckResult>map(identity -> acceptCustomer(command, identity))
                    .orElseGet(PasswordCredentialCheckResult.NotClaimable::new);
        }
        if (progress == PasswordOperationProgress.CONFIRMED
                || progress == PasswordOperationProgress.COMPLETED) {
            return operations.confirmedOwner(operationId)
                    .<PasswordCredentialCheckResult>map(owner ->
                            new PasswordCredentialCheckResult.Verified(
                                    owner.identity(), owner.customer(), owner.subjectId()))
                    .orElseGet(PasswordCredentialCheckResult.NotClaimable::new);
        }
        return new PasswordCredentialCheckResult.Processing();
    }
}
