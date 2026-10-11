package com.vpbank.dcp.infrastructure.adapter.out.redis.codec;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record ServingControlSnapshot(
        ServingState state, UUID generation, String redisRunId,
        UUID controllerId, long controllerFence, Instant leaseUntil) {

    public ServingControlSnapshot {
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(generation, "generation");
        Objects.requireNonNull(redisRunId, "redisRunId");
        Objects.requireNonNull(controllerId, "controllerId");
        Objects.requireNonNull(leaseUntil, "leaseUntil");
        if (redisRunId.isBlank() || controllerFence < 0
                || controllerFence > 9007199254740991L
                || leaseUntil.toEpochMilli() < 0
                || leaseUntil.toEpochMilli() > 9007199254740991L) {
            throw new InvalidAuthorityValueException();
        }
    }
}
