package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.security.Digest32;
import java.util.Objects;
import java.util.UUID;

/**
 * State written by init and read by verify and confirm. The challenge itself is never stored,
 * only its digest. Both public keys are kept in their wire form; {@code enrollmentId} names this
 * exchange to the App and is bound into both encrypted messages.
 */
public record KeyExchange(WrappedServerKey serverKey, String serverPublicKey,
                          Digest32 challengeDigest, String devicePublicKey,
                          Digest32 deviceKeyThumbprint, UUID enrollmentId) {
    public KeyExchange {
        Objects.requireNonNull(serverKey, "serverKey");
        Objects.requireNonNull(challengeDigest, "challengeDigest");
        Objects.requireNonNull(deviceKeyThumbprint, "deviceKeyThumbprint");
        Objects.requireNonNull(enrollmentId, "enrollmentId");
        if (serverPublicKey == null || serverPublicKey.isBlank()
                || devicePublicKey == null || devicePublicKey.isBlank()) {
            throw new IllegalArgumentException("Invalid restricted session value");
        }
    }
}
