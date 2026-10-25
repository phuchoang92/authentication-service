package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/** Init success body: Ksrv's public JWK and the challenge sealed to the device key (DD 20 §6a). */
public record InitEnrollmentResponse(String status, UUID enrollmentId, Map<String, Object> serverPublicJwk,
                                     String challenge, Instant expiresAt) {
    @Override
    public String toString() {
        return "InitEnrollmentResponse[status=" + status + ", enrollmentId=" + enrollmentId + ", redacted]";
    }
}
