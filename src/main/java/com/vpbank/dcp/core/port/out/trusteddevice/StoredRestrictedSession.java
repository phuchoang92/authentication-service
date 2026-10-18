package com.vpbank.dcp.core.port.out.trusteddevice;

import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.security.Digest32;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A restricted session as read back from Valkey. {@code keyExchange} exists from KEY_EXCHANGE
 * on, {@code mfaTransactionId} only at MFA; the compact constructor enforces that pairing.
 */
public record StoredRestrictedSession(UUID sessionId, UUID operationId, SubjectId owner,
                                      CustomerNumber customerNumber, long customerStatusVersion,
                                      String channel, TrustTarget target, Digest32 deviceIdDigest,
                                      LoginKeys keys, String platform, UUID generation,
                                      Instant expiresAt, RestrictedSessionStep step,
                                      int verifyAttempts, KeyExchange keyExchange,
                                      String mfaTransactionId) {
    public StoredRestrictedSession {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(customerNumber, "customerNumber");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(deviceIdDigest, "deviceIdDigest");
        Objects.requireNonNull(keys, "keys");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(generation, "generation");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(step, "step");
        boolean keysExpected = step != RestrictedSessionStep.OPEN;
        boolean mfaExpected = step == RestrictedSessionStep.MFA;
        if (customerStatusVersion < 0 || verifyAttempts < 0
                || keysExpected != (keyExchange != null)
                || mfaExpected != (mfaTransactionId != null)) {
            throw new InvalidRestrictedSessionException();
        }
    }

    @Override
    public String toString() {
        return "StoredRestrictedSession[redacted]";
    }
}
