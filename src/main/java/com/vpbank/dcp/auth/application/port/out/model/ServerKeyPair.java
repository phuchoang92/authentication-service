package com.vpbank.dcp.auth.application.port.out.model;

import lombok.NonNull;


/** Ksrv as JWK text: the public part goes to the app, the private part stays in the restricted session. */
public record ServerKeyPair(@NonNull String publicJwk, @NonNull String privateJwk) {
    @Override
    public String toString() {
        return "ServerKeyPair[redacted]";
    }
}
