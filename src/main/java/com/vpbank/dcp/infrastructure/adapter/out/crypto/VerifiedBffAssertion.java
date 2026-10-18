package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.time.Instant;
import java.util.Objects;

/** Claims of a BFF assertion whose signature, typing, audience and lifetime were verified. */
public record VerifiedBffAssertion(SessionTokenLookup session, String channel, String deviceId,
                                   Digest32 assertionIdDigest, Instant expiresAt) {
    public VerifiedBffAssertion {
        Objects.requireNonNull(session, "session");
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
