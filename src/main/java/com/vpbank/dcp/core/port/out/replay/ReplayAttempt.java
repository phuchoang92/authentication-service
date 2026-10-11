package com.vpbank.dcp.core.port.out.replay;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import java.util.Objects;
import java.util.UUID;

/** A cryptographically verified proof awaiting atomic shared admission. */
public record ReplayAttempt(RequestKeyThumbprint requestKey, Digest32 proofIdDigest, UUID generation) {

    public ReplayAttempt {
        Objects.requireNonNull(requestKey, "requestKey");
        Objects.requireNonNull(proofIdDigest, "proofIdDigest");
        Objects.requireNonNull(generation, "generation");
    }
}
