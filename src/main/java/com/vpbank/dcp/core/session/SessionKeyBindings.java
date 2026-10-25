package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.security.Digest32;
import java.util.Objects;

/** Frozen request/delivery keys and registered device-possession binding. */
public record SessionKeyBindings(Digest32 requestKey,
                                 String requestPublicJwk,
                                 String responsePublicJwk,
                                 Digest32 deviceKey) {
    public SessionKeyBindings {
        Objects.requireNonNull(requestKey, "requestKey");
        Objects.requireNonNull(requestPublicJwk, "requestPublicJwk");
        Objects.requireNonNull(responsePublicJwk, "responsePublicJwk");
        Objects.requireNonNull(deviceKey, "deviceKey");
    }

    @Override
    public String toString() {
        return "SessionKeyBindings[redacted]";
    }
}
