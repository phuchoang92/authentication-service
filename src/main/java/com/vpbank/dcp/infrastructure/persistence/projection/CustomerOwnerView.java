package com.vpbank.dcp.infrastructure.persistence.projection;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Immutable database values; domain restoration belongs to the persistence mapper. */
public record CustomerOwnerView(
        UUID id,
        String customerId,
        String status,
        long statusVersion,
        long lastAccessBlockVersion,
        Instant checkedAt) {
    public CustomerOwnerView {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(checkedAt, "checkedAt");
    }

    @Override
    public String toString() {
        return "CustomerOwnerView[redacted]";
    }
}
