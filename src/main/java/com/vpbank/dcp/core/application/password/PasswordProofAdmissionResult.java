package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import java.util.Objects;
import java.util.UUID;

public sealed interface PasswordProofAdmissionResult {
    record Admitted(VerifiedPasswordProofs proofs, UUID generation)
            implements PasswordProofAdmissionResult {
        public Admitted {
            Objects.requireNonNull(proofs, "proofs");
            Objects.requireNonNull(generation, "generation");
        }
    }

    record Rejected() implements PasswordProofAdmissionResult { }

    record Unavailable() implements PasswordProofAdmissionResult { }
}
