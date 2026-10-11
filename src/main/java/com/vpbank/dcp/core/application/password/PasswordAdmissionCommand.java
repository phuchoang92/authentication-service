package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import java.time.Instant;
import java.util.Objects;

/** Secret-bearing input is never logged or persisted. */
public record PasswordAdmissionCommand(PasswordOperationContext operation,
                                       PasswordVerification credential,
                                       PasswordWireProofs proofs,
                                       Instant now,
                                       Instant credentialDeadline,
                                       Instant journeyDeadline) {

    public PasswordAdmissionCommand {
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(credential, "credential");
        Objects.requireNonNull(proofs, "proofs");
        Objects.requireNonNull(now, "now");
        Objects.requireNonNull(credentialDeadline, "credentialDeadline");
        Objects.requireNonNull(journeyDeadline, "journeyDeadline");
    }

    @Override
    public String toString() {
        return "PasswordAdmissionCommand[redacted]";
    }
}
