package com.vpbank.dcp.core.password;

import java.util.Objects;
import java.util.UUID;

/**
 * Verified App signatures plus the replay generation they reserved. The two always travel
 * together from admission to the login's final action; bundling them keeps every step's
 * signature readable.
 */
public record AdmittedProof(VerifiedPasswordProofs proofs, UUID generation) {
    public AdmittedProof {
        Objects.requireNonNull(proofs, "proofs");
        Objects.requireNonNull(generation, "generation");
    }
}
