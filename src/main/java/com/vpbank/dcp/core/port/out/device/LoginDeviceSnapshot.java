package com.vpbank.dcp.core.port.out.device;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Current database facts; possession and owner policy are evaluated in the use case. */
public record LoginDeviceSnapshot(UUID bindingId, UUID customerId, String channel,
                                  String platform, boolean installationMatches,
                                  boolean active, boolean primary, Instant expiresAt,
                                  long securityVersion, StoredDeviceKey deviceKey) {
    public LoginDeviceSnapshot {
        Objects.requireNonNull(bindingId, "bindingId");
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(deviceKey, "deviceKey");
    }

    public Digest32 deviceKeyThumbprint() {
        return deviceKey.thumbprint();
    }
}
