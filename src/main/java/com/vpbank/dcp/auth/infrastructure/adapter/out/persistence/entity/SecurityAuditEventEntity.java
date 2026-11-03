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
import org.springframework.data.domain.Persistable;

/**
 * Row of SECURITY_AUDIT_EVENT (V5 + V6): append-only activity, inserted by the background writer; never updated.
 * Login rows fill CHANNEL; service-token rows (slice 12) fill SERVICE_ID, SCOPE and, when issued, TOKEN_ID.
 *
 * <p>The ID is assigned here, so Spring Data would otherwise SELECT each row before INSERT to learn
 * whether it exists. {@link Persistable#isNew()} answers "always new": a row is written once and never
 * loaded for a save, so a batch is inserts only.
 */
@Entity
@Table(name = "SECURITY_AUDIT_EVENT")
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class SecurityAuditEventEntity implements Persistable<UUID> {

    @Id
    @Column(name = "ID", columnDefinition = "BINARY(16)", nullable = false)
    private UUID id;

    @Column(name = "EVENT_TYPE", length = 40, nullable = false)
    private String eventType;

    @Column(name = "REASON_CODE", length = 40, nullable = false)
    private String reasonCode;

    @Column(name = "CUSTOMER_ID", length = 16)
    private String customerId;

    @Column(name = "CHANNEL", length = 64)
    private String channel;

    @Column(name = "PLATFORM", length = 24)
    private String platform;

    @Column(name = "SESSION_ID", columnDefinition = "BINARY(16)")
    private UUID sessionId;

    @Column(name = "FAILED_COUNT")
    private Integer failedCount;

    @Column(name = "SERVICE_ID", length = 64)
    private String serviceId;

    @Column(name = "SCOPE", length = 32)
    private String scope;

    @Column(name = "TOKEN_ID", columnDefinition = "BINARY(16)")
    private UUID tokenId;

    @Column(name = "OCCURRED_AT", nullable = false)
    private Instant occurredAt;

    @Column(name = "RECORDED_AT", nullable = false)
    private Instant recordedAt;

    @Override
    public boolean isNew() {
        return true;
    }
}
