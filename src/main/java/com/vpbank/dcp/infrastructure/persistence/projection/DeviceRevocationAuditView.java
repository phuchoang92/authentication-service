package com.vpbank.dcp.infrastructure.persistence.projection;

import java.util.Objects;
import java.util.UUID;

public record DeviceRevocationAuditView(UUID operationId, long deviceSecurityVersion,
                                        boolean primaryCleared) {
    public DeviceRevocationAuditView {
        Objects.requireNonNull(operationId, "operationId");
    }
}
