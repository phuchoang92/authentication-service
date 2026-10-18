package com.vpbank.dcp.core.port.out.device;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Current database facts; possession and owner policy are evaluated in the use case. */
public record LoginDeviceSnapshot(BindingId bindingId, SubjectId owner, String channel,
                                  String platform, boolean deviceIdMatches,
                                  boolean active, boolean primary, Instant expiresAt,
                                  long securityVersion, StoredDeviceKey deviceKey) {
    public LoginDeviceSnapshot {
        Objects.requireNonNull(bindingId, "bindingId");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(deviceKey, "deviceKey");
    }

    public Digest32 deviceKeyThumbprint() {
        return deviceKey.thumbprint();
    }
}
