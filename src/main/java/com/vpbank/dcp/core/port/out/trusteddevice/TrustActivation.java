package com.vpbank.dcp.core.port.out.trusteddevice;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.security.Digest32;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Everything confirm commits in one SQL transaction once MFA passed. Same-typed values are kept
 * apart so they cannot be passed in the wrong order.
 */
public record TrustActivation(UUID operationId, SubjectId owner, long customerStatusVersion,
                              String channel, TrustTarget target, String platform,
                              Digest32 deviceKeyThumbprint, String devicePublicJwk,
                              WrappedServerKey serverKey, String deviceId,
                              Digest32 mfaReceiptDigest, Instant now) {
    public TrustActivation {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(deviceKeyThumbprint, "deviceKeyThumbprint");
        Objects.requireNonNull(devicePublicJwk, "devicePublicJwk");
        Objects.requireNonNull(serverKey, "serverKey");
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(mfaReceiptDigest, "mfaReceiptDigest");
        Objects.requireNonNull(now, "now");
        if (customerStatusVersion < 0) {
            throw new InvalidRestrictedSessionException();
        }
    }

    @Override
    public String toString() {
        return "TrustActivation[redacted]";
    }
}
