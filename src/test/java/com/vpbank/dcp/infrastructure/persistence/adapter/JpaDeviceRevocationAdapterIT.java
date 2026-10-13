package com.vpbank.dcp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.domain.device.DeviceOwnership;
import com.vpbank.dcp.core.domain.device.DeviceRevocationReason;
import com.vpbank.dcp.core.domain.device.SecurityActor;
import com.vpbank.dcp.core.domain.device.SecurityActorType;
import com.vpbank.dcp.core.port.out.device.DeviceRevocationRecordResult;
import com.vpbank.dcp.core.port.out.device.DeviceRevocationRepository;
import com.vpbank.dcp.core.port.out.device.RecordDeviceRevocation;
import java.time.Instant;
import java.time.Clock;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import com.vpbank.dcp.infrastructure.persistence.repository.SecurityAuditPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.TrustedDeviceRevocationPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceRevocationCommandDigest;
import com.vpbank.dcp.infrastructure.persistence.entity.SecurityAuditEventEntity;
import com.vpbank.dcp.infrastructure.persistence.repository.SecurityAuditJpaRepository;

/** The database mutation and its audit must commit or roll back together. */
@Testcontainers
@SpringBootTest(classes = JpaDeviceRevocationAdapterIT.TestConfiguration.class,
        webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "spring.datasource.hikari.maximum-pool-size=5",
        "spring.jpa.hibernate.ddl-auto=none",
        "spring.data.redis.host=127.0.0.1", "spring.data.redis.port=1",
        "spring.data.redis.username=none", "spring.data.redis.password=none",
        "spring.data.redis.ssl.enabled=false"
})
class JpaDeviceRevocationAdapterIT {
    private static final String CHANNEL = "neo-mobile";

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(DockerImageName.parse(
            "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_device_revocation")
            .withUsername("auth_test").withPassword("test-only-password");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @Autowired DeviceRevocationRepository revocations;
    @Autowired JdbcTemplate jdbc;

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @EntityScan(basePackageClasses = SecurityAuditEventEntity.class)
    @EnableJpaRepositories(basePackageClasses = SecurityAuditJpaRepository.class)
    @Import({JpaDeviceRevocationAdapter.class, TrustedDeviceRevocationPersistenceRepository.class,
            SecurityAuditPersistenceRepository.class, DeviceRevocationCommandDigest.class})
    static class TestConfiguration {
        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }

        @Bean
        TransactionTemplate transactionTemplate(PlatformTransactionManager manager) {
            return new TransactionTemplate(manager);
        }
    }

    @Test
    void revokingPrimaryClearsPointerAndRecordsBothEventsExactlyOnce() {
        Fixture fixture = seed(true);
        RecordDeviceRevocation command = command(fixture);

        assertThat(revocations.recordRevocation(command))
                .isEqualTo(new DeviceRevocationRecordResult.Recorded(1, true));
        assertThat(status(fixture.deviceId())).isEqualTo("REVOKED");
        assertThat(primary(fixture.customerId())).isNull();
        assertThatThrownBy(() -> jdbc.update("""
                UPDATE auth_trusted_device SET is_primary = 1 WHERE id = UUID_TO_BIN(?)
                """, fixture.deviceId().toString()))
                .isInstanceOf(org.springframework.dao.DataAccessException.class)
                .hasMessageContaining("ck_trusted_device_primary");
        assertThat(eventCount(command.operationId())).isEqualTo(2);
        assertThat(revocations.recordRevocation(command))
                .isEqualTo(new DeviceRevocationRecordResult.AlreadyRecorded(1, true));
        assertThat(eventCount(command.operationId())).isEqualTo(2);
    }

    @Test
    void revokingNonPrimaryKeepsPointerAndRecordsOneEvent() {
        Fixture fixture = seed(false);
        RecordDeviceRevocation command = command(fixture);

        assertThat(revocations.recordRevocation(command))
                .isEqualTo(new DeviceRevocationRecordResult.Recorded(1, false));
        assertThat(primary(fixture.customerId())).isEqualTo(fixture.primaryId().toString());
        assertThat(eventCount(command.operationId())).isEqualTo(1);
    }

    @Test
    void customerChannelCannotHaveTwoPrimaryDevices() {
        Fixture fixture = seed(false);
        assertThatThrownBy(() -> jdbc.update("""
                UPDATE auth_trusted_device SET is_primary = 1
                 WHERE id = UUID_TO_BIN(?) AND auth_customer_id = UUID_TO_BIN(?) AND channel = ?
                """, fixture.deviceId().toString(), fixture.customerId().toString(), CHANNEL))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThat(primary(fixture.customerId())).isEqualTo(fixture.primaryId().toString());
    }

    @Test
    void wrongOwnerOrChangedOperationCannotRevokeAgain() {
        Fixture fixture = seed(true);
        RecordDeviceRevocation command = command(fixture);
        RecordDeviceRevocation wrongOwner = new RecordDeviceRevocation(
                new DeviceOwnership(UUID.randomUUID(), CHANNEL), fixture.deviceId(),
                UUID.randomUUID(), 0, command.reason(), command.actor(), command.occurredAt());

        assertThat(revocations.recordRevocation(wrongOwner))
                .isInstanceOf(DeviceRevocationRecordResult.Conflict.class);
        RecordDeviceRevocation wrongChannel = new RecordDeviceRevocation(
                new DeviceOwnership(fixture.customerId(), "other-channel"), fixture.deviceId(),
                UUID.randomUUID(), 0, command.reason(), command.actor(), command.occurredAt());
        assertThat(revocations.recordRevocation(wrongChannel))
                .isInstanceOf(DeviceRevocationRecordResult.Conflict.class);
        assertThat(status(fixture.deviceId())).isEqualTo("ACTIVE");
        revocations.recordRevocation(command);
        RecordDeviceRevocation differentOperation = new RecordDeviceRevocation(
                command.owner(), command.bindingId(), UUID.randomUUID(), 0,
                command.reason(), command.actor(), command.occurredAt());
        assertThat(revocations.recordRevocation(differentOperation))
                .isInstanceOf(DeviceRevocationRecordResult.Conflict.class);
    }

    @Test
    void sameOperationWithChangedCommandConflicts() {
        Fixture fixture = seed(true);
        RecordDeviceRevocation command = command(fixture);
        assertThat(revocations.recordRevocation(command))
                .isInstanceOf(DeviceRevocationRecordResult.Recorded.class);

        RecordDeviceRevocation changedReason = new RecordDeviceRevocation(command.owner(),
                command.bindingId(), command.operationId(), command.expectedVersion(),
                DeviceRevocationReason.SECURITY_COMPROMISE, command.actor(), command.occurredAt());
        assertThat(revocations.recordRevocation(changedReason))
                .isInstanceOf(DeviceRevocationRecordResult.Conflict.class);

        RecordDeviceRevocation changedActor = new RecordDeviceRevocation(command.owner(),
                command.bindingId(), command.operationId(), command.expectedVersion(),
                command.reason(), new SecurityActor(SecurityActorType.SYSTEM, "system-test"),
                command.occurredAt());
        assertThat(revocations.recordRevocation(changedActor))
                .isInstanceOf(DeviceRevocationRecordResult.Conflict.class);
        assertThat(eventCount(command.operationId())).isEqualTo(2);
    }

    @Test
    void eventWithoutDigestCannotBeAssumedToMatchRetry() {
        Fixture fixture = seed(false);
        RecordDeviceRevocation command = command(fixture);
        assertThat(revocations.recordRevocation(command))
                .isInstanceOf(DeviceRevocationRecordResult.Recorded.class);
        jdbc.update("""
                UPDATE auth_security_audit_event SET command_digest = NULL
                WHERE operation_id = UUID_TO_BIN(?) AND event_type = 'DEVICE_REVOKED'
                """, command.operationId().toString());

        assertThat(revocations.recordRevocation(command))
                .isInstanceOf(DeviceRevocationRecordResult.Conflict.class);
        assertThat(eventCount(command.operationId())).isEqualTo(1);
    }

    @Test
    void concurrentSameOperationHasOneTransitionAndOneAuditPair() throws Exception {
        Fixture fixture = seed(true);
        RecordDeviceRevocation command = command(fixture);
        CountDownLatch start = new CountDownLatch(1);
        Callable<DeviceRevocationRecordResult> attempt = () -> {
            start.await();
            return revocations.recordRevocation(command);
        };
        try (var workers = Executors.newFixedThreadPool(2)) {
            Future<DeviceRevocationRecordResult> first = workers.submit(attempt);
            Future<DeviceRevocationRecordResult> second = workers.submit(attempt);
            start.countDown();
            var results = java.util.List.of(first.get(), second.get());
            assertThat(results.stream().filter(DeviceRevocationRecordResult.Recorded.class::isInstance).count())
                    .isEqualTo(1);
            assertThat(results.stream().filter(DeviceRevocationRecordResult.AlreadyRecorded.class::isInstance).count())
                    .isEqualTo(1);
        }
        assertThat(eventCount(command.operationId())).isEqualTo(2);
        assertThat(primary(fixture.customerId())).isNull();
        assertThat(securityVersion(fixture.deviceId())).isEqualTo(1);
    }

    @Test
    void auditFailureRollsBackDeviceAndPrimaryChanges() {
        Fixture fixture = seed(true);
        RecordDeviceRevocation command = command(fixture);
        jdbc.update("""
                INSERT INTO auth_security_audit_event
                  (id, auth_customer_id, channel, operation_id, event_sequence, event_type,
                   trusted_device_id, device_security_version, actor_type, actor_id,
                   occurred_at, recorded_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), ?, UUID_TO_BIN(?), 1, 'DEVICE_TRUSTED',
                        UUID_TO_BIN(?), 0, 'SYSTEM', 'test', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, UUID.randomUUID().toString(), fixture.customerId().toString(), CHANNEL,
                command.operationId().toString(), fixture.deviceId().toString());

        assertThatThrownBy(() -> revocations.recordRevocation(command))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThat(status(fixture.deviceId())).isEqualTo("ACTIVE");
        assertThat(primary(fixture.customerId())).isEqualTo(fixture.deviceId().toString());
        assertThat(eventCount(command.operationId())).isEqualTo(1);
    }

    private Fixture seed(boolean primaryTarget) {
        UUID customerId = UUID.randomUUID();
        UUID deviceId = UUID.randomUUID();
        UUID primaryId = primaryTarget ? deviceId : UUID.randomUUID();
        jdbc.update("""
                INSERT INTO auth_customer
                  (id, customer_id, customer_status_version, customer_status_checked_at,
                   status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), ?, 1, UTC_TIMESTAMP(6), 'ELIGIBLE', 'test',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, customerId.toString(), "customer-" + customerId);
        insertDevice(customerId, deviceId);
        if (!primaryTarget) {
            insertDevice(customerId, primaryId);
        }
        jdbc.update("""
                UPDATE auth_trusted_device SET is_primary = 1
                 WHERE id = UUID_TO_BIN(?) AND auth_customer_id = UUID_TO_BIN(?) AND channel = ?
                """, primaryId.toString(), customerId.toString(), CHANNEL);
        return new Fixture(customerId, deviceId, primaryId);
    }

    private void insertDevice(UUID customerId, UUID deviceId) {
        jdbc.update("""
                INSERT INTO auth_trusted_device
                  (id, auth_customer_id, channel, device_id_lookup, device_id_lookup_key_id,
                   device_id_ciphertext, device_id_key_id, platform, label, status,
                   device_public_key, device_public_key_hash, device_key_algorithm,
                   trust_method, trust_policy_version, possession_assurance,
                   trusted_at, expires_at, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), ?, UNHEX(SHA2(?, 256)),
                        'test-lookup-key', X'010203', 'test-encryption-key', 'ANDROID',
                        'Test device', 'ACTIVE', X'01020304', UNHEX(SHA2(?, 256)),
                        'ES256', 'NFC_FACE_SMS_OTP', 'test-policy', 'MFA_KEY_POSSESSION',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6) + INTERVAL 90 DAY,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, deviceId.toString(), customerId.toString(), CHANNEL,
                "installation-" + deviceId, "public-key-" + deviceId);
    }

    private static RecordDeviceRevocation command(Fixture fixture) {
        return new RecordDeviceRevocation(new DeviceOwnership(fixture.customerId(), CHANNEL),
                fixture.deviceId(), UUID.randomUUID(), 0,
                DeviceRevocationReason.CUSTOMER_REQUEST,
                new SecurityActor(SecurityActorType.CUSTOMER, "customer-test"), Instant.now());
    }

    private String status(UUID deviceId) {
        return jdbc.queryForObject("SELECT status FROM auth_trusted_device WHERE id = UUID_TO_BIN(?)",
                String.class, deviceId.toString());
    }

    private long securityVersion(UUID deviceId) {
        return jdbc.queryForObject("""
                SELECT device_security_version FROM auth_trusted_device WHERE id = UUID_TO_BIN(?)
                """, Long.class, deviceId.toString());
    }

    private String primary(UUID customerId) {
        var rows = jdbc.queryForList("""
                SELECT BIN_TO_UUID(id) FROM auth_trusted_device
                 WHERE auth_customer_id = UUID_TO_BIN(?) AND channel = ? AND is_primary = 1
                """, String.class, customerId.toString(), CHANNEL);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private int eventCount(UUID operationId) {
        return jdbc.queryForObject("""
                SELECT COUNT(*) FROM auth_security_audit_event WHERE operation_id = UUID_TO_BIN(?)
                """, Integer.class, operationId.toString());
    }

    private record Fixture(UUID customerId, UUID deviceId, UUID primaryId) { }
}
