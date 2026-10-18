package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.Objects;
import java.util.UUID;

/** {@code attemptsLeft} is present only for a wrong challenge answer. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TrustedDeviceErrorResponse(String code, String message, UUID correlationId,
                                         String nextAction, Integer attemptsLeft)
        implements TrustedDeviceResponse {
    public TrustedDeviceErrorResponse {
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(correlationId, "correlationId");
        Objects.requireNonNull(nextAction, "nextAction");
    }
}
