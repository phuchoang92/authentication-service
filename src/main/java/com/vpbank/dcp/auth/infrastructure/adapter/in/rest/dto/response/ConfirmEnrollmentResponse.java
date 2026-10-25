package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response;

import java.time.Instant;

/** Confirm success body: the new ACTIVE session, its token only inside the compact JWE {@code tokenEnvelope}. */
public record ConfirmEnrollmentResponse(String tokenEnvelope, String status, Instant idleExpiresAt,
                                        Instant absoluteExpiresAt) {
    @Override
    public String toString() {
        return "ConfirmEnrollmentResponse[status=" + status + ", redacted]";
    }
}
