package com.vpbank.dcp.auth.application.port.out.model;

import java.util.Objects;

/** Ksrv as JWK text: the public part goes to the app, the private part stays in the restricted session. */
public record ServerKeyPair(String publicJwk, String privateJwk) {
    public ServerKeyPair {
        Objects.requireNonNull(publicJwk, "publicJwk");
        Objects.requireNonNull(privateJwk, "privateJwk");
    }

    @Override
    public String toString() {
        return "ServerKeyPair[redacted]";
    }
}
