package com.vpbank.dcp.infrastructure.adapter.in.web.error;

import java.util.Objects;
import java.util.UUID;

public record ApiError(String code, String message, UUID correlationId) {

    public ApiError {
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(correlationId, "correlationId");
    }
}
