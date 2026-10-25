package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.security.Digest32;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Claims of a BFF assertion whose signature, typing, audience and lifetime were verified. */
public record VerifiedBffAssertion(UUID sessionId, String channel, String deviceId,
                                   Digest32 assertionIdDigest, Instant expiresAt) {
    public VerifiedBffAssertion {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(assertionIdDigest, "assertionIdDigest");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }

    @Override
    public String toString() {
        return "VerifiedBffAssertion[redacted]";
    }
}
