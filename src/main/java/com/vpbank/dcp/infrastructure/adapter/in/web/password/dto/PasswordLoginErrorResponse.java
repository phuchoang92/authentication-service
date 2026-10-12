package com.vpbank.dcp.infrastructure.adapter.in.web.password.dto;

import java.util.Objects;
import java.util.UUID;

public record PasswordLoginErrorResponse(String code, String message, UUID correlationId,
                                         String nextAction) implements PasswordLoginResponse {
    public PasswordLoginErrorResponse {
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(correlationId, "correlationId");
        Objects.requireNonNull(nextAction, "nextAction");
    }
}
