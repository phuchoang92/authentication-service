package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.Map;

/**
 * {@code POST /api/v1/trusted-device/claim}: the token scanned from the primary device's QR and the public
 * P-256 JWK the new ACTIVE session token must be sealed to.
 */
public record ClaimEnrollmentRequest(

        @NotBlank(message = "{auth.required}")
        @Size(max = 128, message = "{auth.tooLong}")
        String authorizationToken,

        @NotNull(message = "{auth.required}")
        Map<String, Object> tokenEncryptionKey) {

    @Override
    public String toString() {
        return "ClaimEnrollmentRequest[redacted]";
    }
}
