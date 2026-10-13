package com.vpbank.dcp.core.domain.device;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A supplied, invalid candidate is rejected; it cannot silently become a new device.
 */
public final class TrustedDeviceRouting {

    public TrustedDeviceRoute decide(UUID customerId, String channel, String platform,
                                     DeviceCandidate candidate, Instant now) {
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(now, "now");
        if (candidate == null) {
            return TrustedDeviceRoute.NEW_DEVICE;
        }
        if (!customerId.equals(candidate.ownerId()) || !channel.equals(candidate.channel())
                || !platform.equals(candidate.platform()) || !candidate.installationMatches()
                || !candidate.active() || !candidate.expiresAt().isAfter(now)
                || !candidate.possessionVerified()) {
            return TrustedDeviceRoute.REJECTED;
        }
        return candidate.primary()
                ? TrustedDeviceRoute.LAST_TRUSTED : TrustedDeviceRoute.OTHER_TRUSTED;
    }
}
