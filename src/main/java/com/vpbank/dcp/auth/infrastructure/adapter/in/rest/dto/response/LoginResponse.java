package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response;

import java.time.Instant;

/** Login success body: the token only inside the compact JWE {@code tokenEnvelope}. */
public record LoginResponse(String tokenEnvelope, String status, Instant idleExpiresAt, Instant absoluteExpiresAt) {
    @Override
    public String toString() {
        return "LoginResponse[status=" + status + ", redacted]";
    }
}
