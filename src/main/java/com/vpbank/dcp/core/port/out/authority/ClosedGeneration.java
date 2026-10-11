package com.vpbank.dcp.core.port.out.authority;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Must be derived from a committed, fenced SQL authority-control operation. */
public record ClosedGeneration(UUID generation, UUID controllerId, long fence, Instant leaseUntil) {

    public ClosedGeneration {
        Objects.requireNonNull(generation, "generation");
        Objects.requireNonNull(controllerId, "controllerId");
        Objects.requireNonNull(leaseUntil, "leaseUntil");
        if (fence < 1 || fence > 9007199254740991L) {
            throw new InvalidAuthorityLeaseChangeException();
        }
    }
}
