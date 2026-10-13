package com.vpbank.dcp.core.port.out.device;

import com.vpbank.dcp.core.domain.device.DeviceOwnership;
import com.vpbank.dcp.core.domain.device.DeviceRevocationReason;
import com.vpbank.dcp.core.domain.device.SecurityActor;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A durable database transition; online denial is a separate required acknowledgement. */
public record RecordDeviceRevocation(DeviceOwnership owner, UUID bindingId, UUID operationId,
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
            throw new InvalidDeviceRevocationVersionException();
        }
    }
}
