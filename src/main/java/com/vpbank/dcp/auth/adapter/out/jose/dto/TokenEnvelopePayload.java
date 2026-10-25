package com.vpbank.dcp.auth.adapter.out.jose.dto;

import java.time.Instant;

/** What the app finds after decrypting the envelope (DD 06): the token and the session's deadlines. */
public record TokenEnvelopePayload(String token, String status, String customerId, Instant idleExpiresAt,
                                   Instant absoluteExpiresAt) {
    @Override
    public String toString() {
        return "TokenEnvelopePayload[status=" + status + ", redacted]";
    }
}
