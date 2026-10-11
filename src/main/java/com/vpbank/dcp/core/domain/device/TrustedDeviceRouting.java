package com.vpbank.dcp.core.domain.device;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A supplied, invalid candidate is rejected; it cannot silently become a new device.
 */
public final class TrustedDeviceRouting {

    public TrustedDeviceRoute decide(UUID subjectId, String appId, String installationHash,
                                     UUID lastSuccessfulBindingId, DeviceCandidate candidate,
                                     Instant now) {
        Objects.requireNonNull(subjectId, "subjectId");
        Objects.requireNonNull(appId, "appId");
        Objects.requireNonNull(installationHash, "installationHash");
        Objects.requireNonNull(now, "now");
        if (candidate == null) {
            return TrustedDeviceRoute.NEW_DEVICE;
        }
        if (!subjectId.equals(candidate.ownerId()) || !appId.equals(candidate.appId())
                || !installationHash.equals(candidate.installationHash())
                || !candidate.active() || !candidate.expiresAt().isAfter(now)
                || !candidate.keyActive() || !candidate.possessionVerified()) {
            return TrustedDeviceRoute.REJECTED;
        }
        return candidate.bindingId().equals(lastSuccessfulBindingId)
                ? TrustedDeviceRoute.LAST_TRUSTED : TrustedDeviceRoute.OTHER_TRUSTED;
    }
}
