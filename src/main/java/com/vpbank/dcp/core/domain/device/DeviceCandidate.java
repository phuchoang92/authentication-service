package com.vpbank.dcp.core.domain.device;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record DeviceCandidate(UUID bindingId, UUID ownerId, String appId, String installationHash,
                              boolean active, Instant expiresAt, boolean keyActive,
                              boolean possessionVerified) {

    public DeviceCandidate {
        Objects.requireNonNull(bindingId, "bindingId");
        Objects.requireNonNull(ownerId, "ownerId");
        Objects.requireNonNull(appId, "appId");
        Objects.requireNonNull(installationHash, "installationHash");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }
}
