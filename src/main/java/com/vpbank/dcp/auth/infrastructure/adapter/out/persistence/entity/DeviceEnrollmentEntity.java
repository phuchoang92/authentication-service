package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity;

import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common.AuditedEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Row of TRUSTED_DEVICE_ENROLLMENT (phase 4) for the init → verify → confirm flow. The old-device
 * approval columns (REQUESTER_*, AUTHORIZATION_*) stay NULL/0; CREATION_IDEMPOTENCY_DIGEST is the
 * SHA-256 of the restricted session ID, so a retried init finds the same row (UQ_DE_CREATION).
 */
@Entity
@Table(name = "TRUSTED_DEVICE_ENROLLMENT")
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class DeviceEnrollmentEntity extends AuditedEntity {
    @Id
    @Column(name = "ID", columnDefinition = "BINARY(16)", nullable = false)
    private UUID id;

    @Column(name = "CUSTOMER_ID", length = 16, nullable = false)
    private String customerId;

    @Column(name = "CHANNEL", length = 64, nullable = false)
    private String channel;

    @Enumerated(EnumType.STRING)
    @Column(name = "PURPOSE", length = 32, nullable = false)
    private EnrollmentPurpose purpose;

    @Enumerated(EnumType.STRING)
    @Column(name = "STATE", length = 32, nullable = false)
    private EnrollmentState state;

    @Column(name = "TARGET_DEVICE_ID", columnDefinition = "BINARY(16)")
    private UUID targetDeviceId;

    @Column(name = "TARGET_CLIENT_DEVICE_ID_LOOKUP", columnDefinition = "BINARY(32)")
    private byte[] targetClientDeviceIdLookup;

    @Column(name = "CLIENT_DEVICE_ID_LOOKUP_KEY_ID", length = 64)
    private String clientDeviceIdLookupKeyId;

    @Column(name = "MULTIFACTOR_ID")
    private String multifactorId;

    @Column(name = "CONFIRMED_MFA_METHOD", length = 64)
    private String confirmedMfaMethod;

    @Column(name = "MFA_CONFIRMED_AT")
    private Instant mfaConfirmedAt;

    @Column(name = "AUTHORIZATION_ATTEMPTS", nullable = false)
    private int authorizationAttempts;

    @Column(name = "EXPIRES_AT", nullable = false)
    private Instant expiresAt;

    @Column(name = "CREATION_IDEMPOTENCY_DIGEST", columnDefinition = "BINARY(32)", nullable = false)
    private byte[] creationIdempotencyDigest;

    @Version
    @Column(name = "VERSION", nullable = false)
    private long version;

    /** Copies one step the aggregate decided; the only write path. The attempt counter reuses AUTHORIZATION_ATTEMPTS. */
    public void applyState(EnrollmentState state, String multifactorId, int verifyAttempts, Instant mfaConfirmedAt) {
        this.state = state;
        this.multifactorId = multifactorId;
        this.authorizationAttempts = verifyAttempts;
        if (mfaConfirmedAt != null) {
            this.confirmedMfaMethod = "FACE";
            this.mfaConfirmedAt = mfaConfirmedAt;
        }
    }
}
