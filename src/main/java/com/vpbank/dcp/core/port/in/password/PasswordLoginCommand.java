package com.vpbank.dcp.core.port.in.password;

import com.vpbank.dcp.core.port.out.credential.PasswordVerification;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;

import java.time.Instant;
import java.util.Objects;

/**
 * Secret-bearing input is never logged or persisted.
 */
public record PasswordLoginCommand(PasswordOperationContext operation,
                                   PasswordVerification credential,
                                   PasswordWireProofs proofs,
                                   Instant now,
                                   Instant credentialDeadline,
                                   Instant journeyDeadline) {

    public PasswordLoginCommand {
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(credential, "credential");
        Objects.requireNonNull(proofs, "proofs");
        Objects.requireNonNull(now, "now");
        Objects.requireNonNull(credentialDeadline, "credentialDeadline");
        Objects.requireNonNull(journeyDeadline, "journeyDeadline");
    }

    @Override
    public String toString() {
        return "PasswordLoginCommand[redacted]";
    }
}
