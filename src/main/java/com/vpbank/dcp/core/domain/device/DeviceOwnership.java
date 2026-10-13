package com.vpbank.dcp.core.domain.device;

import java.util.Objects;
import java.util.UUID;

public record DeviceOwnership(UUID customerId, String channel) {
    public DeviceOwnership {
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(channel, "channel");
        if (channel.isBlank() || channel.length() > 64) {
            throw new InvalidDeviceOwnershipException();
        }
    }
}
