package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.security.Digest32;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A restricted session as read back from Valkey: what the login pinned, plus its progress. */
public record StoredRestrictedSession(UUID sessionId, RestrictedSession login,
                                      Digest32 deviceIdDigest, Instant expiresAt,
                                      RestrictedProgress progress) {
    public StoredRestrictedSession {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(login, "login");
        Objects.requireNonNull(deviceIdDigest, "deviceIdDigest");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(progress, "progress");
    }

    @Override
    public String toString() {
        return "StoredRestrictedSession[redacted]";
    }
}
