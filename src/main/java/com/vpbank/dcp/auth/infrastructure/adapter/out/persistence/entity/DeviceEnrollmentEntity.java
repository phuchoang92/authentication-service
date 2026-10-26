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
 * Row of TRUSTED_DEVICE_ENROLLMENT (phase 4), shared by the primary enrollment (slice 5) and the approval
 * by the primary device (slice 6). CREATION_IDEMPOTENCY_DIGEST is the SHA-256 of the restricted session
 * ID, so a retried request finds the same row (UQ_DE_CREATION) and the claim is bound to that session.
 *
 * <p>Column use by purpose: MULTIFACTOR_ID / CONFIRMED_MFA_METHOD / MFA_CONFIRMED_AT hold the one MFA of
 * the flow (the device's FACE, or the approver's FACE + OTP); AUTHORIZATION_ATTEMPTS counts the device's
 * challenge answers for TRUST_DEVICE and the QR token claims for TRUST_DEVICE_APPROVAL; the other
 * AUTHORIZATION_* columns, ACTOR_DEVICE_ID and REQUESTER_CLIENT_DEVICE_ID_LOOKUP are approval-only.
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

    /** The primary device that approved (slice 6). */
    @Column(name = "ACTOR_DEVICE_ID", columnDefinition = "BINARY(16)")
    private UUID actorDeviceId;

    /** The requesting installation's lookup (slice 6); the same installation as the target. */
    @Column(name = "REQUESTER_CLIENT_DEVICE_ID_LOOKUP", columnDefinition = "BINARY(32)")
    private byte[] requesterClientDeviceIdLookup;

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

    @Column(name = "AUTHORIZATION_TOKEN_DIGEST", columnDefinition = "BINARY(32)")
    private byte[] authorizationTokenDigest;

    @Column(name = "AUTHORIZATION_EXPIRES_AT")
    private Instant authorizationExpiresAt;

    @Column(name = "AUTHORIZATION_CONSUMED_AT")
    private Instant authorizationConsumedAt;

    /** The session whose claim completed the approval: its creation digest (slice 6). */
    @Column(name = "AUTHORIZED_SESSION_REF_DIGEST", columnDefinition = "BINARY(32)")
    private byte[] authorizedSessionRefDigest;

    @Column(name = "EXPIRES_AT", nullable = false)
    private Instant expiresAt;

    @Column(name = "CREATION_IDEMPOTENCY_DIGEST", columnDefinition = "BINARY(32)", nullable = false)
    private byte[] creationIdempotencyDigest;

    @Version
    @Column(name = "VERSION", nullable = false)
    private long version;

    /**
     * Copies one step the aggregate decided; the only write path. {@code attempts} is the counter of the
     * flow's purpose (see the class comment); {@code mfaConfirmedAt} is set once, when the MFA passed.
     */
    public void applyState(EnrollmentState state, String multifactorId, String confirmedMfaMethod, int attempts,
                           Instant mfaConfirmedAt) {
        this.state = state;
        this.multifactorId = multifactorId;
        this.confirmedMfaMethod = confirmedMfaMethod;
        this.authorizationAttempts = attempts;
        if (mfaConfirmedAt != null && this.mfaConfirmedAt == null) {
            this.mfaConfirmedAt = mfaConfirmedAt;
        }
    }

    /** The approval path's own columns (slice 6): the approver, the token digest and deadline, the claim. */
    public void applyApproval(UUID actorDeviceId, byte[] authorizationTokenDigest, Instant authorizationExpiresAt,
                              Instant authorizationConsumedAt) {
        this.actorDeviceId = actorDeviceId;
        this.authorizationTokenDigest = authorizationTokenDigest;
        this.authorizationExpiresAt = authorizationExpiresAt;
        this.authorizationConsumedAt = authorizationConsumedAt;
        if (authorizationConsumedAt != null) {
            this.authorizedSessionRefDigest = this.creationIdempotencyDigest;
        }
    }
}
