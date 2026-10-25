package com.vpbank.dcp.core.password;

import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.security.RequestKeyThumbprint;
import java.util.Objects;

public record VerifiedPasswordProofs(RequestKeyThumbprint requestKey,
                                     Digest32 responseKeyThumbprint,
                                     Digest32 deviceKeyThumbprint,
                                     PasswordProofIds proofIds,
                                     String requestPublicJwk,
                                     String responsePublicJwk) {

    public VerifiedPasswordProofs {
        Objects.requireNonNull(requestKey, "requestKey");
        Objects.requireNonNull(responseKeyThumbprint, "responseKeyThumbprint");
        Objects.requireNonNull(proofIds, "proofIds");
        Objects.requireNonNull(requestPublicJwk, "requestPublicJwk");
        Objects.requireNonNull(responsePublicJwk, "responsePublicJwk");
        if ((deviceKeyThumbprint == null) != (proofIds.deviceKey() == null)) {
            throw new IllegalArgumentException("Password operation is invalid");
        }
    }

    @Override
    public String toString() {
        return "VerifiedPasswordProofs[redacted]";
    }
}
