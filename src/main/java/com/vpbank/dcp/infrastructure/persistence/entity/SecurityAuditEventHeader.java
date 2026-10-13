package com.vpbank.dcp.infrastructure.persistence.entity;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Columns shared by the two audit events written for one device revocation. */
public record SecurityAuditEventHeader(UUID id, UUID customerId, String channel,
                                       UUID operationId, int sequence, String actorType,
                                       String actorId, Instant occurredAt, Instant recordedAt) {
    public SecurityAuditEventHeader {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(actorType, "actorType");
        Objects.requireNonNull(actorId, "actorId");
        Objects.requireNonNull(occurredAt, "occurredAt");
        Objects.requireNonNull(recordedAt, "recordedAt");
    }

    @Override
    public String toString() {
        return "SecurityAuditEventHeader[redacted]";
    }
}
