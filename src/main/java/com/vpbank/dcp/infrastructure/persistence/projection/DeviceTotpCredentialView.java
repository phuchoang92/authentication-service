package com.vpbank.dcp.infrastructure.persistence.projection;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Locked database row, never exposed through an API or log. */
public record DeviceTotpCredentialView(UUID id, byte[] secretCiphertext,
                                       String secretKeyId, long lastAcceptedStep,
                                       int failedAttempts, Instant blockedUntil, long version) {
    public DeviceTotpCredentialView {
        Objects.requireNonNull(id, "id");
        secretCiphertext = Objects.requireNonNull(secretCiphertext, "secretCiphertext").clone();
        Objects.requireNonNull(secretKeyId, "secretKeyId");
    }

    @Override
    public byte[] secretCiphertext() {
        return secretCiphertext.clone();
    }

    @Override
    public String toString() {
        return "DeviceTotpCredentialView[redacted]";
    }
}
