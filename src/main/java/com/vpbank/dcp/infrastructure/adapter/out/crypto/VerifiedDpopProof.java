package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import java.time.Instant;
import java.util.Objects;

public record VerifiedDpopProof(
        RequestKeyThumbprint requestKey,
        Digest32 proofIdDigest,
        Instant issuedAt) {

    public VerifiedDpopProof {
        Objects.requireNonNull(requestKey, "requestKey");
        Objects.requireNonNull(proofIdDigest, "proofIdDigest");
        Objects.requireNonNull(issuedAt, "issuedAt");
    }
}
