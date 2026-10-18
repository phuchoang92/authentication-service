package com.vpbank.dcp.core.domain.device;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import java.time.Instant;
import java.util.Objects;

/**
 * A supplied, invalid candidate is rejected; it cannot silently become a new device.
 * Only a candidate this customer owns and proves can lapse instead of being rejected.
 */
public final class DeviceTrustPolicy {

    public DeviceTrustDecision decide(SubjectId owner, String channel, String platform,
                                     DeviceCandidate candidate, Instant now) {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(now, "now");
        if (candidate == null) {
            return DeviceTrustDecision.NEW_DEVICE;
        }
        // Identity checks come first: a binding that is not this customer's, or that its key
        // does not prove, is rejected and never treated as lapsed or new.
        if (!owner.equals(candidate.owner()) || !channel.equals(candidate.channel())
                || !platform.equals(candidate.platform()) || !candidate.deviceIdMatches()
                || !candidate.possessionVerified()) {
            return DeviceTrustDecision.REJECTED;
        }
        // A proven binding of this customer that was revoked or has expired must be trusted
        // again through the trusted-device flow, which requires MFA.
        if (!candidate.active() || !candidate.expiresAt().isAfter(now)) {
            return DeviceTrustDecision.TRUST_LAPSED;
        }
        return candidate.primary()
                ? DeviceTrustDecision.LAST_TRUSTED : DeviceTrustDecision.OTHER_TRUSTED;
    }
}
