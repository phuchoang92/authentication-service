package com.vpbank.dcp.core.device;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A durable database transition; online denial is a separate required acknowledgement.
 * Seven components on purpose: every one is part of the idempotency digest and the audit row,
 * so a retry with any changed field is a different command.
 */
public record RecordDeviceRevocation(DeviceOwnership owner, BindingId bindingId, UUID operationId,
                                     long expectedVersion, DeviceRevocationReason reason,
                                     SecurityActor actor, Instant occurredAt) {
    public RecordDeviceRevocation {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(bindingId, "bindingId");
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(actor, "actor");
        Objects.requireNonNull(occurredAt, "occurredAt");
        if (expectedVersion < 0 || expectedVersion >= 9007199254740991L) {
            throw new IllegalArgumentException("Device version is outside the supported range");
        }
    }
}
