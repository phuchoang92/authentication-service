package com.vpbank.dcp.core.port.out.session;

import java.time.Instant;
import java.util.Objects;

/** Locked trusted-device row facts that decide whether a session may still be published. */
public record StoredDeviceSecurity(boolean active, Instant expiresAt, boolean primary) {

    public StoredDeviceSecurity {
        Objects.requireNonNull(expiresAt, "expiresAt");
    }
}
