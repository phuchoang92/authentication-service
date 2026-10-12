package com.vpbank.dcp.infrastructure.adapter.in.web.password.dto;

import java.util.Objects;
import java.util.UUID;

public record PasswordLoginProcessingResponse(String status, UUID operationId,
        String nextAction, UUID correlationId) implements PasswordLoginResponse {
    public PasswordLoginProcessingResponse {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(nextAction, "nextAction");
        Objects.requireNonNull(correlationId, "correlationId");
    }
}
