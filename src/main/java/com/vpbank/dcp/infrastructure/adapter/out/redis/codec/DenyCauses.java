package com.vpbank.dcp.infrastructure.adapter.out.redis.codec;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public record DenyCauses(boolean customer, boolean administrative, Optional<UUID> resetOperationId) {

    public DenyCauses {
        Objects.requireNonNull(resetOperationId, "resetOperationId");
    }
}
