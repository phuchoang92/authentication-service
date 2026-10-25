package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.security.Digest32;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A restricted session ready to publish, with its protected delivery. Never holds the plaintext
 * token: storage is keyed by {@code sessionId} and keeps {@code secretDigest}; the App receives
 * {@code tokenEnvelope}. Seven components because each is written once at creation and the
 * delivery pair cannot be split from the session it was issued for.
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
