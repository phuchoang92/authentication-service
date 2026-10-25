package com.vpbank.dcp.core.device;

import com.vpbank.dcp.core.security.Digest32;
import java.util.Objects;

/**
 * Current database facts of one trusted-device row; possession and owner policy are evaluated
 * by {@link DeviceTrustPolicy}. Seven components because these are the facts of one locked row
 * that the policy and session issuance read together; grouping them further would add a type
 * with no meaning of its own.
 */
public record LoginDeviceSnapshot(BindingId bindingId, DeviceOwnership owner, String platform,
                                  boolean deviceIdMatches, DeviceStanding standing,
                                  long securityVersion, StoredDeviceKey deviceKey) {
    public LoginDeviceSnapshot {
        Objects.requireNonNull(bindingId, "bindingId");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(standing, "standing");
        Objects.requireNonNull(deviceKey, "deviceKey");
    }

    public Digest32 deviceKeyThumbprint() {
        return deviceKey.thumbprint();
    }
}
