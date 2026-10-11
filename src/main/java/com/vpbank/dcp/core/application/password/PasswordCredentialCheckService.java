package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.core.port.out.keycloak.KeycloakVerificationUnavailableException;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerificationOutcome;
import com.vpbank.dcp.core.port.out.password.PasswordCredentialRecordResult;
import com.vpbank.dcp.core.port.out.password.PasswordDispatchResult;
import com.vpbank.dcp.core.port.out.password.PasswordOperationStore;
import java.time.Clock;
import java.util.Objects;
import java.util.UUID;

/** Claims one durable dispatch before sending a password to Keycloak. */
public final class PasswordCredentialCheckService {

    private final PasswordAdmissionService admission;
    private final PasswordOperationStore operations;
    private final DirectGrantPasswordVerifier keycloak;
    private final CustomerSnapshotCheckService customers;
    private final Clock clock;

    public PasswordCredentialCheckService(PasswordAdmissionService admission,
                                          PasswordOperationStore operations,
                                          DirectGrantPasswordVerifier keycloak,
                                          CustomerSnapshotCheckService customers,
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
        if (reserved instanceof PasswordAdmissionResult.Existing) {
            return new PasswordCredentialCheckResult.Processing();
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
            return new PasswordCredentialCheckResult.Processing();
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
        CustomerSnapshotCheckResult customer = customers.check(verified.identity(), clock.instant());
        if (customer instanceof CustomerSnapshotCheckResult.Rejected) {
            PasswordCredentialRecordResult saved = operations.recordRejection(operationId);
            return saved == PasswordCredentialRecordResult.RECORDED
                    ? new PasswordCredentialCheckResult.Rejected()
                    : new PasswordCredentialCheckResult.NotClaimable();
        }
        if (customer instanceof CustomerSnapshotCheckResult.Unavailable) {
            PasswordCredentialRecordResult saved = operations.recordUncertain(operationId);
            return saved == PasswordCredentialRecordResult.NOT_RECORDABLE
                    ? new PasswordCredentialCheckResult.NotClaimable()
                    : new PasswordCredentialCheckResult.Processing();
        }
        CustomerSnapshotCheckResult.Eligible eligible = (CustomerSnapshotCheckResult.Eligible) customer;
        // Current local owner/guard state must be committed before this can authorize a token.
        return new PasswordCredentialCheckResult.Verified(verified.identity(), eligible.customer());
    }
}
