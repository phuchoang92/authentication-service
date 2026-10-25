package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** {@code POST /api/v1/trusted-device/verify}: the challenge re-sealed to Ksrv as a compact JWE. */
public record VerifyEnrollmentRequest(
        @NotBlank(message = "{auth.required}") @Size(max = 4096, message = "{auth.tooLong}") String challengeResponse) {
    @Override
    public String toString() {
        return "VerifyEnrollmentRequest[redacted]";
    }
}
