package com.vpbank.dcp.core.device;

import com.vpbank.dcp.core.security.Digest32;
import java.time.Instant;
import java.util.Objects;

/**
 * A supplied, invalid binding is rejected; it cannot silently become a new device.
 * Only a binding this customer owns and proves can lapse instead of being rejected.
 */
public final class DeviceTrustPolicy {

    /**
     * {@code stored} is the claimed binding's row, or null when none was claimed;
     * {@code presentedDeviceKey} is the thumbprint the login proved possession of.
     */
    public DeviceTrustDecision decide(DeviceOwnership owner, String platform,
                                      LoginDeviceSnapshot stored, Digest32 presentedDeviceKey,
                                      Instant now) {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(now, "now");
        if (stored == null) {
            return DeviceTrustDecision.NEW_DEVICE;
        }
        // Identity checks come first: a binding that is not this customer's, or that its key
        // does not prove, is rejected and never treated as lapsed or new.
        if (!owner.equals(stored.owner()) || !platform.equals(stored.platform())
                || !stored.deviceIdMatches()
                || !stored.deviceKeyThumbprint().equals(presentedDeviceKey)) {
            return DeviceTrustDecision.REJECTED;
        }
        // A proven binding of this customer that was revoked or has expired must be trusted
        // again through the trusted-device flow, which requires MFA.
        if (!stored.standing().trustedAt(now)) {
            return DeviceTrustDecision.TRUST_LAPSED;
        }
        return stored.standing().primary()
                ? DeviceTrustDecision.LAST_TRUSTED : DeviceTrustDecision.OTHER_TRUSTED;
    }
}
