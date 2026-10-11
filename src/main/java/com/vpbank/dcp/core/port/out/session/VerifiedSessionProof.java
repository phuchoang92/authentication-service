package com.vpbank.dcp.core.port.out.session;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.util.Objects;

public record VerifiedSessionProof(Digest32 proofId, Digest32 nonceDigest, String nonce) {
    public VerifiedSessionProof {
        Objects.requireNonNull(proofId);
        Objects.requireNonNull(nonceDigest);
        Objects.requireNonNull(nonce);
    }
}
