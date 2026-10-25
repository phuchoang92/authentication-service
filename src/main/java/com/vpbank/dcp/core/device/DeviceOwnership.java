package com.vpbank.dcp.core.device;

import com.vpbank.dcp.core.customer.SubjectId;
import java.util.Objects;

public record DeviceOwnership(SubjectId subject, String channel) {
    public DeviceOwnership {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(channel, "channel");
        if (channel.isBlank() || channel.length() > 64) {
            throw new IllegalArgumentException("Device owner is invalid");
        }
    }
}
