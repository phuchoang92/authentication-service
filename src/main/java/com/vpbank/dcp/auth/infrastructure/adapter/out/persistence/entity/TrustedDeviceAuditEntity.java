package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** Row of TRUSTED_DEVICE_AUDIT: append-only; one business operation writes events 0..n under one correlation ID. */
@Entity
@Table(name = "TRUSTED_DEVICE_AUDIT")
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class TrustedDeviceAuditEntity {

    @Id
    @Column(name = "ID", columnDefinition = "BINARY(16)", nullable = false)
    private UUID id;

    @Column(name = "CUSTOMER_ID", length = 16, nullable = false)
    private String customerId;

    @Column(name = "CORRELATION_ID", length = 128, nullable = false)
    private String correlationId;

    @Column(name = "EVENT_SEQUENCE", nullable = false)
    private int eventSequence;

    @Column(name = "EVENT_TYPE", length = 64, nullable = false)
    private String eventType;

    @Column(name = "CAUSE", length = 24, nullable = false)
    private String cause;

    @Column(name = "ACTOR_TYPE", length = 24, nullable = false)
    private String actorType;

    @Column(name = "ACTOR_SUBJECT", nullable = false)
    private String actorSubject;

    @Column(name = "ACTOR_DEVICE_ID", columnDefinition = "BINARY(16)")
    private UUID actorDeviceId;

    @Column(name = "ACTOR_CHANNEL", length = 64)
    private String actorChannel;

    @Column(name = "TARGET_DEVICE_ID", columnDefinition = "BINARY(16)")
    private UUID targetDeviceId;

    @Column(name = "TARGET_CHANNEL", length = 64)
    private String targetChannel;

    @Column(name = "TARGET_ACTION", length = 64)
    private String targetAction;

    @Column(name = "REASON_CODE", length = 64, nullable = false)
    private String reasonCode;

    @Column(name = "POLICY_VERSION", length = 64, nullable = false)
    private String policyVersion;

    @Column(name = "OCCURRED_AT", nullable = false)
    private Instant occurredAt;

    @Column(name = "METADATA", columnDefinition = "JSON")
    private String metadata;

    @Column(name = "ENROLLMENT_ID", columnDefinition = "BINARY(16)")
    private UUID enrollmentId;
}
