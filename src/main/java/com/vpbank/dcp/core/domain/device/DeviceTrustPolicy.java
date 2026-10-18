package com.vpbank.dcp.core.domain.device;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import java.time.Instant;
import java.util.Objects;

/**
 * A supplied, invalid candidate is rejected; it cannot silently become a new device.
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
        if (!owner.equals(candidate.owner()) || !channel.equals(candidate.channel())
                || !platform.equals(candidate.platform()) || !candidate.installationMatches()
                || !candidate.active() || !candidate.expiresAt().isAfter(now)
                || !candidate.possessionVerified()) {
            return DeviceTrustDecision.REJECTED;
        }
        return candidate.primary()
                ? DeviceTrustDecision.LAST_TRUSTED : DeviceTrustDecision.OTHER_TRUSTED;
    }
}
