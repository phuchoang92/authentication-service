package com.vpbank.dcp.core.port.out.trusteddevice;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A restricted session ready to publish, with its protected delivery. Never holds the plaintext
 * token: storage is keyed by {@code sessionId} and keeps {@code secretDigest}; the App receives
 * {@code tokenEnvelope}.
 */
public record PreparedRestrictedSession(RestrictedSession session, UUID sessionId,
                                        Digest32 secretDigest, Digest32 deviceIdDigest,
                                        Instant expiresAt, String tokenEnvelope, String receipt) {
    public PreparedRestrictedSession {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(secretDigest, "secretDigest");
        Objects.requireNonNull(deviceIdDigest, "deviceIdDigest");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(tokenEnvelope, "tokenEnvelope");
        Objects.requireNonNull(receipt, "receipt");
    }

    @Override
    public String toString() {
        return "PreparedRestrictedSession[redacted]";
    }
}
