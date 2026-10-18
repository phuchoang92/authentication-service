package com.vpbank.dcp.core.domain.device;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import java.time.Instant;
import java.util.Objects;

public record DeviceCandidate(BindingId bindingId, SubjectId owner, String channel, String platform,
                              boolean deviceIdMatches, boolean active, boolean primary,
                              Instant expiresAt, boolean possessionVerified) {

    public DeviceCandidate {
        Objects.requireNonNull(bindingId, "bindingId");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }
}
