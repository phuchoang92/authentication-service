package com.vpbank.dcp.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** Append-only audit row. It is not a device or session authority. */
@Entity
@Table(name = "auth_security_audit_event")
public class SecurityAuditEventEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "id", columnDefinition = "binary(16)", nullable = false)
    private UUID id;

    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "auth_customer_id", columnDefinition = "binary(16)", nullable = false)
    private UUID authCustomerId;

    @Column(name = "channel", nullable = false)
    private String channel;

    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "operation_id", columnDefinition = "binary(16)", nullable = false)
    private UUID operationId;

    @Column(name = "event_sequence", nullable = false)
    private int eventSequence;

    @Column(name = "event_type", nullable = false)
    private String eventType;

    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "trusted_device_id", columnDefinition = "binary(16)")
    private UUID trustedDeviceId;

    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "previous_primary_device_id", columnDefinition = "binary(16)")
    private UUID previousPrimaryDeviceId;

    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "new_primary_device_id", columnDefinition = "binary(16)")
    private UUID newPrimaryDeviceId;

    @Column(name = "device_security_version")
    private Long deviceSecurityVersion;

    @Column(name = "reason_code")
    private String reasonCode;

    @Column(name = "actor_type", nullable = false)
    private String actorType;

    @Column(name = "actor_id", nullable = false)
    private String actorId;

    @JdbcTypeCode(SqlTypes.TIMESTAMP_UTC)
    @Column(name = "occurred_at", columnDefinition = "datetime(6)", nullable = false)
    private Instant occurredAt;

    @JdbcTypeCode(SqlTypes.TIMESTAMP_UTC)
    @Column(name = "recorded_at", columnDefinition = "datetime(6)", nullable = false)
    private Instant recordedAt;

    @Column(name = "command_digest", columnDefinition = "binary(32)")
    private byte[] commandDigest;

    @Column(name = "mfa_receipt_digest", columnDefinition = "binary(32)")
    private byte[] mfaReceiptDigest;

    protected SecurityAuditEventEntity() {
    }

    private SecurityAuditEventEntity(SecurityAuditEventHeader header, String type) {
        id = header.id();
        authCustomerId = header.customerId();
        channel = header.channel();
        operationId = header.operationId();
        eventSequence = header.sequence();
        eventType = type;
        actorType = header.actorType();
        actorId = header.actorId();
        occurredAt = header.occurredAt();
        recordedAt = header.recordedAt();
    }

    public static SecurityAuditEventEntity deviceRevoked(SecurityAuditEventHeader header,
                                                          UUID bindingId, long securityVersion,
                                                          String reasonCode, byte[] commandDigest) {
        SecurityAuditEventEntity event = new SecurityAuditEventEntity(header, "DEVICE_REVOKED");
        event.trustedDeviceId = bindingId;
        event.deviceSecurityVersion = securityVersion;
        event.reasonCode = reasonCode;
        event.commandDigest = commandDigest.clone();
        return event;
    }

    /** A binding trusted after MFA; the receipt that authorised it is recorded. */
    public static SecurityAuditEventEntity deviceTrusted(SecurityAuditEventHeader header,
                                                          UUID bindingId, long securityVersion,
                                                          byte[] mfaReceiptDigest) {
        SecurityAuditEventEntity event = new SecurityAuditEventEntity(header, "DEVICE_TRUSTED");
        event.trustedDeviceId = bindingId;
        event.deviceSecurityVersion = securityVersion;
        event.mfaReceiptDigest = mfaReceiptDigest.clone();
        return event;
    }

    /** A revocation the service made itself, such as REPLACED or DEVICE_LIMIT. */
    public static SecurityAuditEventEntity deviceRevokedBySystem(SecurityAuditEventHeader header,
                                                                  UUID bindingId, long securityVersion,
                                                                  String reasonCode) {
        SecurityAuditEventEntity event = new SecurityAuditEventEntity(header, "DEVICE_REVOKED");
        event.trustedDeviceId = bindingId;
        event.deviceSecurityVersion = securityVersion;
        event.reasonCode = reasonCode;
        return event;
    }

    /** {@code previous} is null when the customer had no primary before. */
    public static SecurityAuditEventEntity primaryChanged(SecurityAuditEventHeader header,
                                                           UUID previous, UUID next) {
        SecurityAuditEventEntity event = new SecurityAuditEventEntity(header, "PRIMARY_DEVICE_CHANGED");
        event.previousPrimaryDeviceId = previous;
        event.newPrimaryDeviceId = next;
        return event;
    }

    public static SecurityAuditEventEntity primaryCleared(SecurityAuditEventHeader header,
                                                           UUID bindingId) {
        SecurityAuditEventEntity event = new SecurityAuditEventEntity(header, "PRIMARY_DEVICE_CHANGED");
        event.previousPrimaryDeviceId = bindingId;
        return event;
    }

    public UUID operationId() {
        return operationId;
    }

    public long deviceSecurityVersion() {
        return deviceSecurityVersion;
    }

    public byte[] commandDigest() {
        return commandDigest == null ? null : commandDigest.clone();
    }

    @Override
    public String toString() {
        return "SecurityAuditEventEntity[redacted]";
    }
}
