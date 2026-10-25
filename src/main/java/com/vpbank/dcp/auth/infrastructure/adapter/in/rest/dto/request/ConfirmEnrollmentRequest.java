package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request;

import jakarta.validation.constraints.NotNull;
import java.util.Map;

/**
 * {@code POST /api/v1/trusted-device/confirm}: the public P-256 JWK the new ACTIVE session token is
 * sealed to (DD 20 §6a: the trusted flow uses its own key, not the login one).
 */
public record ConfirmEnrollmentRequest(@NotNull(message = "{auth.required}") Map<String, Object> tokenEncryptionKey) {
    @Override
    public String toString() {
        return "ConfirmEnrollmentRequest[redacted]";
    }
}
