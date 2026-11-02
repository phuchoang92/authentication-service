package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.model.SecurityAuditEvent;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.SecurityEventReason;
import com.vpbank.dcp.auth.domain.enums.SecurityEventType;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.SecurityAuditEventEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.SecurityAuditEventJpaRepository;
import com.vpbank.dcp.auth.infrastructure.config.JpaConfiguration;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** SECURITY_AUDIT_EVENT (V5) on real MySQL: the entity matches the table, a batch is one transaction, nullable columns stay null. */
@Testcontainers
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=validate", "spring.flyway.enabled=true"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(JpaConfiguration.class)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class SecurityAuditEventPersistenceAdapterIT {

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.4");
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final Instant DECIDED_AT = Instant.parse("2026-10-31T09:00:00.123456Z");
    private static final Instant WRITTEN_AT = Instant.parse("2026-10-31T09:00:00.654321Z");

    @DynamicPropertySource
    static void settings(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @Autowired SecurityAuditEventJpaRepository rows;
    @Autowired PlatformTransactionManager transactionManager;
    @Autowired JdbcClient jdbc;
    private SecurityAuditEventPersistenceAdapter writer;

    @BeforeEach
    void clean() {
        jdbc.sql("DELETE FROM SECURITY_AUDIT_EVENT").update();
        writer = new SecurityAuditEventPersistenceAdapter(
                rows,
                new TransactionTemplate(transactionManager),
                Clock.fixed(WRITTEN_AT, ZoneOffset.UTC));
    }

    @Test
    void aBatchLandsAsOneRowPerEventWithTheWriterClockAsRecordedAt() {
        SessionId sessionId = SessionId.random();
        writer.writeBatch(List.of(
                event(SecurityEventType.LOGIN_FAILED, SecurityEventReason.WRONG_PASSWORD, ALICE, 1, null),
                event(SecurityEventType.LOGIN_SUCCEEDED, SecurityEventReason.FULL_SESSION, ALICE, null, sessionId),
                event(SecurityEventType.LOGIN_FAILED, SecurityEventReason.UNKNOWN_USER, null, null, null)));

        assertThat(rows.count()).isEqualTo(3);

        List<SecurityAuditEventEntity> alice = rows.findByCustomerIdOrderByOccurredAtAscIdAsc(ALICE.value());
        assertThat(alice).hasSize(2);
        assertThat(alice).extracting(SecurityAuditEventEntity::getRecordedAt).containsOnly(WRITTEN_AT);
        assertThat(alice).extracting(SecurityAuditEventEntity::getOccurredAt).containsOnly(DECIDED_AT);

        SecurityAuditEventEntity success = alice.stream()
                .filter(row -> row.getEventType().equals("LOGIN_SUCCEEDED"))
                .findFirst().orElseThrow();
        assertThat(success.getReasonCode()).isEqualTo("FULL_SESSION");
        assertThat(success.getChannel()).isEqualTo("MOBILE");
        assertThat(success.getPlatform()).isEqualTo("ANDROID");
        assertThat(success.getSessionId()).isEqualTo(sessionId.value());
        assertThat(success.getFailedCount()).isNull();

        Integer unknownUserRows = jdbc.sql("SELECT COUNT(*) FROM SECURITY_AUDIT_EVENT WHERE CUSTOMER_ID IS NULL AND SESSION_ID IS NULL")
                .query(Integer.class).single();
        assertThat(unknownUserRows).isEqualTo(1);
    }

    @Test
    void anEmptyBatchWritesNothing() {
        writer.writeBatch(List.of());

        assertThat(rows.count()).isZero();
    }

    private static SecurityAuditEvent event(SecurityEventType type, SecurityEventReason reason, CustomerId customerId,
                                            Integer failedCount, SessionId sessionId) {
        assertThat(reason.type()).isEqualTo(type);
        return SecurityAuditEvent.builder()
                .reason(reason)
                .customerId(customerId)
                .channel(Channel.MOBILE)
                .platform(DevicePlatform.ANDROID)
                .sessionId(sessionId)
                .failedCount(failedCount)
                .occurredAt(DECIDED_AT)
                .build();
    }
}
