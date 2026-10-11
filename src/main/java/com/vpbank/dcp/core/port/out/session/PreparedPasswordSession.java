package com.vpbank.dcp.core.port.out.session;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Exact candidate and encrypted delivery, never a plaintext token or session authority. */
public record PreparedPasswordSession(PasswordSessionFacts facts, UUID intentId,
                                      UUID sessionId, UUID generation,
                                      LookupKeyVersion lookupVersion, Digest32 lookupDigest,
                                      Digest32 candidateDigest,
                                      String tokenEnvelope, String receipt, String dpopNonce,
                                      SessionDeadlines deadlines, Instant deliveryDeadline) {
    public PreparedPasswordSession {
        Objects.requireNonNull(facts);
        Objects.requireNonNull(intentId);
        Objects.requireNonNull(sessionId);
        Objects.requireNonNull(generation);
        Objects.requireNonNull(lookupVersion);
        Objects.requireNonNull(lookupDigest);
        Objects.requireNonNull(candidateDigest);
        Objects.requireNonNull(tokenEnvelope);
        Objects.requireNonNull(receipt);
        Objects.requireNonNull(dpopNonce);
        Objects.requireNonNull(deadlines);
        Objects.requireNonNull(deliveryDeadline);
    }

    @Override
    public String toString() {
        return "PreparedPasswordSession[redacted]";
    }
}
