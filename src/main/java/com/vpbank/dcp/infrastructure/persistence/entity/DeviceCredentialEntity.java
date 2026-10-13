package com.vpbank.dcp.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** Persistence state for the current device TOTP credential. Never log this entity. */
@Entity
@Table(name = "auth_device_credential")
public class DeviceCredentialEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "id", columnDefinition = "binary(16)", nullable = false)
    private UUID id;

    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "trusted_device_id", columnDefinition = "binary(16)", nullable = false)
    private UUID trustedDeviceId;

    @Column(name = "secret_ciphertext", nullable = false)
    private byte[] secretCiphertext;

    @Column(name = "secret_key_id", nullable = false)
    private String secretKeyId;

    @Column(name = "status", nullable = false)
    private String status;

    @Column(name = "last_accepted_step", nullable = false)
    private long lastAcceptedStep;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @JdbcTypeCode(SqlTypes.TIMESTAMP_UTC)
    @Column(name = "blocked_until", columnDefinition = "datetime(6)")
    private Instant blockedUntil;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    @Column(name = "activated_at", columnDefinition = "datetime(6)", nullable = false)
    private LocalDateTime activatedAt;

    @Column(name = "revoked_at", columnDefinition = "datetime(6)")
    private LocalDateTime revokedAt;

    protected DeviceCredentialEntity() {
    }

    public UUID id() {
        return id;
    }

    public byte[] secretCiphertext() {
        return secretCiphertext.clone();
    }

    public String secretKeyId() {
        return secretKeyId;
    }

    public long lastAcceptedStep() {
        return lastAcceptedStep;
    }

    public int failedAttempts() {
        return failedAttempts;
    }

    public Instant blockedUntil() {
        return blockedUntil;
    }

    public long version() {
        return version;
    }

    public void acceptStep(long step) {
        lastAcceptedStep = step;
        failedAttempts = 0;
        blockedUntil = null;
    }

    public void recordFailure(int attempts, Instant until) {
        failedAttempts = attempts;
        blockedUntil = until;
    }

    @Override
    public String toString() {
        return "DeviceCredentialEntity[redacted]";
    }
}
