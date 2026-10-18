package com.vpbank.dcp.core.port.out.session;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.util.Objects;
import java.util.UUID;

/** Stable publication identity and digest of the exact prepared candidate. */
public record SessionCandidate(UUID intentId, UUID sessionId, UUID generation,
                               Digest32 secretDigest, Digest32 candidateDigest) {
    public SessionCandidate {
        Objects.requireNonNull(intentId);
        Objects.requireNonNull(sessionId);
        Objects.requireNonNull(generation);
        Objects.requireNonNull(secretDigest);
        Objects.requireNonNull(candidateDigest);
    }

    @Override
    public String toString() {
        return "SessionCandidate[redacted]";
    }
}
