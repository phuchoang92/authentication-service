package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.security.Digest32;
import java.util.Objects;

/**
 * The App keys proven at login, kept so the session issued at confirm is bound to the same Kreq
 * and delivered to the same Kenc. The two JWKs are not adjacent, so they cannot be swapped.
 */
public record LoginKeys(String requestPublicJwk, Digest32 requestKeyThumbprint,
                        String responsePublicJwk) {
    public LoginKeys {
        Objects.requireNonNull(requestKeyThumbprint, "requestKeyThumbprint");
        if (requestPublicJwk == null || requestPublicJwk.isBlank()
                || responsePublicJwk == null || responsePublicJwk.isBlank()) {
            throw new IllegalArgumentException("Invalid restricted session value");
        }
    }
}
