package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.domain.security.Digest32;

import java.util.Objects;

public record InspectedEnvelope(String recipientKid, Digest32 compactDigest) {

    public InspectedEnvelope {
        Objects.requireNonNull(recipientKid, "recipientKid");
        Objects.requireNonNull(compactDigest, "compactDigest");
    }
}
