package com.vpbank.dcp.core.port.out.authority;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A fenced durable change prepared by the recovery controller, not an admission decision. */
public record AuthorityLeaseChange(
        String bankScope,
        long expectedVersion,
        long expectedFence,
        long nextFence,
        UUID generation,
        String redisRunId,
        UUID controllerId,
        Instant leaseUntil) {

    public AuthorityLeaseChange {
        Objects.requireNonNull(bankScope, "bankScope");
        Objects.requireNonNull(generation, "generation");
        Objects.requireNonNull(redisRunId, "redisRunId");
        Objects.requireNonNull(controllerId, "controllerId");
        Objects.requireNonNull(leaseUntil, "leaseUntil");
        if (bankScope.isBlank() || redisRunId.isBlank() || expectedVersion < 0
                || expectedFence < 0 || nextFence <= expectedFence
                || nextFence > 9007199254740991L || expectedVersion >= 9007199254740991L) {
            throw new InvalidAuthorityLeaseChangeException();
        }
    }
}
