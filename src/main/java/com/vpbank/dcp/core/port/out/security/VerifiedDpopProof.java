package com.vpbank.dcp.core.port.out.security;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import java.time.Instant;
import java.util.Objects;

public record VerifiedDpopProof(
        RequestKeyThumbprint requestKey,
        Digest32 proofIdDigest,
        Instant issuedAt,
        String publicJwk,
        Verification verification) {

    public enum Verification { VERIFIED, DISABLED_FOR_NON_PRODUCTION }

    public VerifiedDpopProof(RequestKeyThumbprint requestKey, Digest32 proofIdDigest,
                             Instant issuedAt, String publicJwk) {
        this(requestKey, proofIdDigest, issuedAt, publicJwk, Verification.VERIFIED);
    }

    public VerifiedDpopProof {
        Objects.requireNonNull(requestKey, "requestKey");
        Objects.requireNonNull(proofIdDigest, "proofIdDigest");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(publicJwk, "publicJwk");
        Objects.requireNonNull(verification, "verification");
    }
    @Override
    public String toString() { return "VerifiedDpopProof[redacted]"; }
}
