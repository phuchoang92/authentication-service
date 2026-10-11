package com.vpbank.dcp.core.port.out.password;

import java.time.Instant;
import java.util.Objects;

public record PasswordProofRequest(PasswordOperationContext operation,
                                   PasswordWireProofs wire, Instant now) {

    public PasswordProofRequest {
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(wire, "wire");
        Objects.requireNonNull(now, "now");
    }

    @Override
    public String toString() {
        return "PasswordProofRequest[redacted]";
    }
}
