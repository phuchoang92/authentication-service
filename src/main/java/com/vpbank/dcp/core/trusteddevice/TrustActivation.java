package com.vpbank.dcp.core.trusteddevice;

import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.session.KeyExchange;
import com.vpbank.dcp.core.session.RestrictedSession;
import java.time.Instant;
import java.util.Objects;

/**
 * Everything confirm commits in one SQL transaction once MFA passed: what the login pinned,
 * the completed key exchange, and the App device ID (held in memory only until it is protected).
 */
public record TrustActivation(RestrictedSession login, KeyExchange exchange, String deviceId,
                              Digest32 mfaReceiptDigest, Instant now) {
    public TrustActivation {
        Objects.requireNonNull(login, "login");
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(mfaReceiptDigest, "mfaReceiptDigest");
        Objects.requireNonNull(now, "now");
    }

    @Override
    public String toString() {
        return "TrustActivation[redacted]";
    }
}
