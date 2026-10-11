package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.util.Objects;

/** The digest is reserved separately in shared Redis before any enrollment mutation. */
public record VerifiedEnrollmentProof(Digest32 proofIdDigest) {

    public VerifiedEnrollmentProof {
        Objects.requireNonNull(proofIdDigest, "proofIdDigest");
    }
}
