package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.model.SecurityAuditEvent;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.SecurityEventReason;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.SecurityAuditEventEntity;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** Stored names are frozen codes; the row ID is minted here; absent values stay NULL. */
class SecurityAuditPersistenceMapperTest {
    private static final Instant OCCURRED_AT = Instant.parse("2026-10-31T09:00:00Z");
    private static final Instant RECORDED_AT = OCCURRED_AT.plusSeconds(10);

    @Test
    void aSuccessRowCarriesTheCodesTheCustomerTheSessionAndBothTimes() {
        SessionId sessionId = SessionId.random();
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .reason(SecurityEventReason.FULL_SESSION)
                .customerId(new CustomerId("90359"))
                .channel(Channel.MOBILE)
                .platform(DevicePlatform.ANDROID)
                .sessionId(sessionId)
                .occurredAt(OCCURRED_AT)
                .build();

        SecurityAuditEventEntity row = SecurityAuditPersistenceMapper.toEntity(event, RECORDED_AT);

        assertThat(row.getId()).isNotNull();
        assertThat(row.getEventType()).isEqualTo("LOGIN_SUCCEEDED");
        assertThat(row.getReasonCode()).isEqualTo("FULL_SESSION");
        assertThat(row.getCustomerId()).isEqualTo("90359");
        assertThat(row.getChannel()).isEqualTo("MOBILE");
        assertThat(row.getPlatform()).isEqualTo("ANDROID");
        assertThat(row.getSessionId()).isEqualTo(sessionId.value());
        assertThat(row.getFailedCount()).isNull();
        assertThat(row.getOccurredAt()).isEqualTo(OCCURRED_AT);
        assertThat(row.getRecordedAt()).isEqualTo(RECORDED_AT);
        assertThat(row.isNew()).isTrue();
    }

    @Test
    void anUnknownUserRowKeepsEveryOptionalColumnNullAndEachRowGetsItsOwnId() {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .reason(SecurityEventReason.UNKNOWN_USER)
                .channel(Channel.WEB)
                .occurredAt(OCCURRED_AT)
                .build();

        SecurityAuditEventEntity first = SecurityAuditPersistenceMapper.toEntity(event, RECORDED_AT);
        SecurityAuditEventEntity second = SecurityAuditPersistenceMapper.toEntity(event, RECORDED_AT);

        assertThat(first.getEventType()).isEqualTo("LOGIN_FAILED");
        assertThat(first.getCustomerId()).isNull();
        assertThat(first.getPlatform()).isNull();
        assertThat(first.getSessionId()).isNull();
        assertThat(first.getFailedCount()).isNull();
        assertThat(first.getId()).isNotEqualTo(second.getId());
    }
}
