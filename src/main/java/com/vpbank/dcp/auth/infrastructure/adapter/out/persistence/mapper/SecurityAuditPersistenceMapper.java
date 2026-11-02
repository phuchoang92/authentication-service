package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper;

import com.vpbank.dcp.auth.application.port.out.model.SecurityAuditEvent;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.SecurityAuditEventEntity;
import java.time.Instant;
import java.util.UUID;

/** Event → SECURITY_AUDIT_EVENT row. Enums are stored by name; the row ID is minted here. */
public final class SecurityAuditPersistenceMapper {
    private SecurityAuditPersistenceMapper() {
    }

    public static SecurityAuditEventEntity toEntity(SecurityAuditEvent event, Instant recordedAt) {
        CustomerId customerId = event.customerId();
        SessionId sessionId = event.sessionId();
        return SecurityAuditEventEntity.builder()
                .id(UUID.randomUUID())
                .eventType(event.eventType().name())
                .reasonCode(event.reason().name())
                .customerId(customerId == null ? null : customerId.value())
                .channel(event.channel().name())
                .platform(event.platform() == null ? null : event.platform().name())
                .sessionId(sessionId == null ? null : sessionId.value())
                .failedCount(event.failedCount())
                .occurredAt(event.occurredAt())
                .recordedAt(recordedAt)
                .build();
    }
}
