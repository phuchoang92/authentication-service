package com.vpbank.dcp.core.domain.device;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import java.util.Objects;

public record DeviceOwnership(SubjectId subject, String channel) {
    public DeviceOwnership {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(channel, "channel");
        if (channel.isBlank() || channel.length() > 64) {
            throw new InvalidDeviceOwnershipException();
        }
    }
}
