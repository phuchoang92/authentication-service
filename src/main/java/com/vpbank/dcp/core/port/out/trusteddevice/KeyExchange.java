package com.vpbank.dcp.core.port.out.trusteddevice;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.util.Objects;

/**
 * State written by init and read by verify and confirm. The challenge itself is never stored,
 * only its digest; the device key is stored as a public JWK.
 */
public record KeyExchange(WrappedServerKey serverKey, String serverPublicJwk,
                          Digest32 challengeDigest, String devicePublicJwk,
                          Digest32 deviceKeyThumbprint) {
    public KeyExchange {
        Objects.requireNonNull(serverKey, "serverKey");
        Objects.requireNonNull(challengeDigest, "challengeDigest");
        Objects.requireNonNull(deviceKeyThumbprint, "deviceKeyThumbprint");
        if (serverPublicJwk == null || serverPublicJwk.isBlank()
                || devicePublicJwk == null || devicePublicJwk.isBlank()) {
            throw new InvalidRestrictedSessionException();
        }
    }
}
