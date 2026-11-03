package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response;

import java.time.Instant;

/** The issued service token. {@code toString} hides the token. */
public record ServiceTokenResponse(String token, String tokenType, String scope, Instant expiresAt) {
    @Override
    public String toString() {
        return "ServiceTokenResponse[token=redacted, tokenType=" + tokenType + ", scope=" + scope + ", expiresAt=" + expiresAt + "]";
    }
}
