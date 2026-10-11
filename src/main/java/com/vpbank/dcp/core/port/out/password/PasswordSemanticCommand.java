package com.vpbank.dcp.core.port.out.password;

import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import java.util.Objects;

/** A password-bearing command exists only in memory for digesting and one KC attempt. */
public final class PasswordSemanticCommand {

    private final PasswordOperationContext operation;
    private final PasswordVerification credential;
    private final VerifiedPasswordProofs proofs;

    public PasswordSemanticCommand(PasswordOperationContext operation,
                                   PasswordVerification credential,
                                   VerifiedPasswordProofs proofs) {
        this.operation = Objects.requireNonNull(operation, "operation");
        this.credential = Objects.requireNonNull(credential, "credential");
        this.proofs = Objects.requireNonNull(proofs, "proofs");
        if (!operation.username().equals(credential.username())
                || (operation.claimedBindingId() == null) != (proofs.deviceKeyThumbprint() == null)) {
            throw new InvalidPasswordOperationException();
        }
    }

    public PasswordOperationContext operation() { return operation; }
    public PasswordVerification credential() { return credential; }
    public VerifiedPasswordProofs proofs() { return proofs; }

    @Override
    public String toString() { return "PasswordSemanticCommand[redacted]"; }
}
