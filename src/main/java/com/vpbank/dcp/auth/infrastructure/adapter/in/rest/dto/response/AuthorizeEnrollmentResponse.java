package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response;

import java.time.Instant;

/** Authorize body: the one-time token the primary device renders as a QR for the new device. */
public record AuthorizeEnrollmentResponse(String status, String enrollmentId, String authorizationToken, Instant expiresAt) {
    @Override
    public String toString() {
        return "AuthorizeEnrollmentResponse[status=" + status + ", enrollmentId=" + enrollmentId + ", redacted]";
    }
}
