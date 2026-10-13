package com.vpbank.dcp.core.domain.device;

import java.util.Objects;
import java.util.UUID;

public record DeviceOwnership(UUID customerId, String appId) {
    public DeviceOwnership {
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(appId, "appId");
        if (appId.isBlank() || appId.length() > 64) {
            throw new InvalidDeviceOwnershipException();
        }
    }
}
