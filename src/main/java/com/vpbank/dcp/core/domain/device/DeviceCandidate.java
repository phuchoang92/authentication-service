package com.vpbank.dcp.core.domain.device;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record DeviceCandidate(UUID bindingId, UUID ownerId, String channel, String platform,
                              boolean installationMatches, boolean active, boolean primary,
                              Instant expiresAt, boolean possessionVerified) {

    public DeviceCandidate {
        Objects.requireNonNull(bindingId, "bindingId");
        Objects.requireNonNull(ownerId, "ownerId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }
}
