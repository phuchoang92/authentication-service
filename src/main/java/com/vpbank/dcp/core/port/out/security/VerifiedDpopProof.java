package com.vpbank.dcp.core.port.out.security;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import java.time.Instant;
import java.util.Objects;

public record VerifiedDpopProof(
        RequestKeyThumbprint requestKey,
        Digest32 proofIdDigest,
        Instant issuedAt,
        String publicJwk) {

    public VerifiedDpopProof {
        Objects.requireNonNull(requestKey, "requestKey");
        Objects.requireNonNull(proofIdDigest, "proofIdDigest");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(publicJwk, "publicJwk");
    }
    @Override
    public String toString() { return "VerifiedDpopProof[redacted]"; }
}
