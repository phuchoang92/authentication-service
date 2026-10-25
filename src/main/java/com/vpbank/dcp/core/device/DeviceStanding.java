package com.vpbank.dcp.core.device;

import java.time.Instant;
import java.util.Objects;

/** Whether a trusted-device row may still be used, and whether it is the owner's primary. */
public record DeviceStanding(boolean active, Instant expiresAt, boolean primary) {

    public DeviceStanding {
        Objects.requireNonNull(expiresAt, "expiresAt");
    }

    /** Active and not yet expired. */
    public boolean trustedAt(Instant now) {
        return active && now.isBefore(expiresAt);
    }
}
