package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.core.port.out.keycloak.KeycloakVerificationUnavailableException;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerificationOutcome;
import com.vpbank.dcp.core.port.out.password.PasswordCredentialRecordResult;
import com.vpbank.dcp.core.port.out.password.PasswordDispatchResult;
import com.vpbank.dcp.core.port.out.password.PasswordOperationStore;
import java.util.Objects;
import java.util.UUID;

/** Claims one durable dispatch before sending a password to Keycloak. */
public final class PasswordCredentialCheckService {

    private final PasswordOperationStore operations;
    private final DirectGrantPasswordVerifier keycloak;

    public PasswordCredentialCheckService(PasswordOperationStore operations,
                                          DirectGrantPasswordVerifier keycloak) {
        this.operations = Objects.requireNonNull(operations, "operations");
        this.keycloak = Objects.requireNonNull(keycloak, "keycloak");
    }

    public PasswordCredentialCheckResult check(UUID operationId, PasswordVerification credential) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(credential, "credential");
        PasswordDispatchResult claim = operations.claimDispatch(operationId);
        if (claim == PasswordDispatchResult.ALREADY_CLAIMED) {
            return new PasswordCredentialCheckResult.Processing();
        }
        if (claim == PasswordDispatchResult.NOT_CLAIMABLE) {
            return new PasswordCredentialCheckResult.NotClaimable();
        }

        PasswordVerificationOutcome outcome;
        try {
            outcome = keycloak.verify(credential);
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
        // This identity must be continued and durably accepted with Customer before any token is issued.
        return new PasswordCredentialCheckResult.Verified(verified.identity());
    }
}
