package com.vpbank.dcp.core.port.out.trusteddevice;

import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * What a NEED_TRUSTED_DEVICE login pins. It grants no banking access: only the trusted-device
 * API may use it, and every step re-checks the customer and device.
 *
 * <p>{@code deviceId} stays in memory only; storage keeps a digest of it.
 */
public record RestrictedSession(UUID operationId, SubjectId owner, CustomerNumber customerNumber,
                                long customerStatusVersion, String channel, TrustTarget target,
                                String deviceId, LoginKeys keys, String platform,
                                UUID generation) {
    private static final Set<String> PLATFORMS = Set.of("ANDROID", "IOS");

    public RestrictedSession {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(customerNumber, "customerNumber");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(keys, "keys");
        Objects.requireNonNull(generation, "generation");
        if (customerStatusVersion < 0 || channel == null || channel.isBlank()
                || channel.length() > 64 || deviceId == null || deviceId.isBlank()
                || !PLATFORMS.contains(platform)) {
            throw new InvalidRestrictedSessionException();
        }
    }

    @Override
    public String toString() {
        return "RestrictedSession[redacted]";
    }
}
