package com.vpbank.dcp.infrastructure.adapter.out.persistence.schema;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "server.ssl.enabled=false",
        "auth.authority.scope=bank-test-neo",
        "auth.ingress.external-origin=https://api.bank.test",
        "auth.ingress.allowed-workload-uris=spiffe://bank.test/mobile-bff",
        "spring.datasource.hikari.maximum-pool-size=10",
        "spring.data.redis.host=127.0.0.1",
        "spring.data.redis.port=1",
        "spring.data.redis.ssl.enabled=false"
})
class AuthenticationSchemaMysqlIT {

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(
            DockerImageName.parse("mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_schema_test")
            .withUsername("auth_test")
            .withPassword("test-only-password");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void migrationsPreserveOwnershipConstraintsAndRemoveAuthorityControl() {
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME REGEXP '^auth_'
                """, Integer.class)).isEqualTo(20);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'auth_customer'
                """, Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'auth_subject'
                """, Integer.class)).isZero();
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE
                 WHERE CONSTRAINT_SCHEMA = DATABASE()
                   AND CONSTRAINT_NAME = 'fk_identity_subject'
                   AND REFERENCED_TABLE_NAME = 'auth_customer'
                """, Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'auth_authority_control'
                """, Integer.class)).isZero();
    }

    @Test
    void schemaEnforcesUniqueCustomerAndIdentityOwnership() {
        String customerId = "customer-" + UUID.randomUUID();
        UUID firstSubject = UUID.randomUUID();
        insertSubject(firstSubject, customerId);
        assertThatThrownBy(() -> insertSubject(UUID.randomUUID(), customerId))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);

        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO auth_identity_link
                (id, subject_id, issuer, provider_subject, status, created_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), UNHEX(REPLACE(?, '-', '')),
                        'https://issuer.bank.test', ?, 'ACTIVE', UTC_TIMESTAMP(6))
                """, UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                "sub-" + UUID.randomUUID()))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }

    @Test
    void compositeDeviceOwnershipAndLiveInstallationUniquenessAreDatabaseConstraints() {
        UUID subject = UUID.randomUUID();
        insertSubject(subject, "customer-" + UUID.randomUUID());
        jdbc.update("""
                INSERT INTO auth_subject_app
                (subject_id, app_id, status, version, created_at, updated_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), 'neo-mobile', 'ACTIVE', 0,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subject.toString());
        String installation = UUID.randomUUID().toString();
        insertDeviceBinding(subject, "neo-mobile", installation);

        assertThatThrownBy(() -> insertDeviceBinding(subject, "neo-mobile", installation))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThatThrownBy(() -> insertDeviceBinding(subject, "other-app", installation))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }

    @Test
    void softwareKeyMigrationRejectsHardwareAssuranceClaim() {
        UUID subject = UUID.randomUUID();
        insertSubject(subject, "customer-" + UUID.randomUUID());
        jdbc.update("""
                INSERT INTO auth_subject_app
                (subject_id, app_id, status, version, created_at, updated_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), 'neo-mobile', 'ACTIVE', 0,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subject.toString());

        assertThatThrownBy(() -> insertDeviceBinding(subject, "neo-mobile",
                UUID.randomUUID().toString(), "HARDWARE_KEY"))
                .isInstanceOf(org.springframework.dao.DataAccessException.class);
        insertDeviceBinding(subject, "neo-mobile", UUID.randomUUID().toString(), "NONE");
    }

    @Test
    void passwordOperationRequiresDigestKeyAndNewDevicePendingIntentNeedsNoBinding() {
        UUID subject = UUID.randomUUID();
        UUID journey = UUID.randomUUID();
        UUID operation = UUID.randomUUID();
        insertSubject(subject, "customer-" + UUID.randomUUID());
        jdbc.update("""
                INSERT INTO auth_subject_app
                (subject_id, app_id, status, version, created_at, updated_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), 'neo-mobile', 'ACTIVE', 0,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subject.toString());
        jdbc.update("""
                INSERT INTO auth_login_journey
                (id, subject_id, app_id, method, purpose, installation_hash, request_jkt,
                 request_public_jwk, state, credential_deadline, journey_deadline,
                 created_at, updated_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), UNHEX(REPLACE(?, '-', '')),
                        'neo-mobile', 'PASSWORD', 'LOGIN', UNHEX(REPEAT('11', 32)),
                        UNHEX(REPEAT('22', 32)), '{}', 'PENDING_MFA',
                        UTC_TIMESTAMP(6) + INTERVAL 2 MINUTE,
                        UTC_TIMESTAMP(6) + INTERVAL 5 MINUTE,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, journey.toString(), subject.toString());

        assertThatThrownBy(() -> insertPasswordOperation(operation, journey, subject, null))
                .isInstanceOf(org.springframework.dao.DataAccessException.class)
                .hasCauseInstanceOf(java.sql.SQLException.class)
                .satisfies(failure -> assertThat(((java.sql.SQLException) failure.getCause()).getErrorCode())
                        .isEqualTo(3819));
        insertPasswordOperation(operation, journey, subject, "h1");

        UUID intent = UUID.randomUUID();
        insertPendingIntent(intent, journey, operation, subject, "33");
        assertThat(jdbc.queryForObject("""
                SELECT issuance_slot FROM auth_authority_intent
                 WHERE id = UNHEX(REPLACE(?, '-', ''))
                """, Integer.class, intent.toString())).isEqualTo(1);

        UUID anotherOperation = UUID.randomUUID();
        insertPasswordOperation(anotherOperation, journey, subject, "h1");
        assertThatThrownBy(() -> insertPendingIntent(UUID.randomUUID(), journey,
                anotherOperation, subject, "33"))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThatThrownBy(() -> jdbc.update("""
                UPDATE auth_authority_intent SET kind = 'ACTIVATE'
                 WHERE id = UNHEX(REPLACE(?, '-', ''))
                """, intent.toString()))
                .isInstanceOf(org.springframework.dao.DataAccessException.class)
                .hasCauseInstanceOf(java.sql.SQLException.class)
                .satisfies(failure -> assertThat(((java.sql.SQLException) failure.getCause()).getErrorCode())
                        .isEqualTo(3819));
    }

    private void insertPasswordOperation(UUID operation, UUID journey, UUID subject,
                                         String digestKeyId) {
        jdbc.update("""
                INSERT INTO auth_operation
                (id, journey_id, subject_id, app_id, owner_scope, kind, idempotency_digest,
                 command_digest, command_digest_key_id, request_jkt, state, deadline,
                 created_at, updated_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), UNHEX(REPLACE(?, '-', '')),
                        UNHEX(REPLACE(?, '-', '')), 'neo-mobile', UNHEX(SHA2(?, 256)),
                        'PASSWORD_LOGIN', UNHEX(SHA2(?, 256)), UNHEX(REPEAT('44', 32)),
                        ?, UNHEX(REPEAT('22', 32)), 'RESERVED',
                        UTC_TIMESTAMP(6) + INTERVAL 5 MINUTE,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, operation.toString(), journey.toString(), subject.toString(),
                operation.toString(), operation.toString(), digestKeyId);
    }

    private void insertPendingIntent(UUID intent, UUID journey, UUID operation,
                                     UUID subject, String lookupDigestByte) {
        jdbc.update("""
                INSERT INTO auth_authority_intent
                (id, subject_id, app_id, journey_id, operation_id, binding_id, request_jkt,
                 kind, state, generation, session_id, token_lookup_digest,
                 lookup_key_version, expected_session_version, customer_security_version,
                 credential_security_version, device_security_version, candidate_digest,
                 deadline, created_at, updated_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), UNHEX(REPLACE(?, '-', '')),
                        'neo-mobile', UNHEX(REPLACE(?, '-', '')),
                        UNHEX(REPLACE(?, '-', '')), NULL, UNHEX(REPEAT('22', 32)),
                        'ISSUE_PENDING', 'PREPARED', UNHEX(REPLACE(?, '-', '')),
                        UNHEX(REPLACE(?, '-', '')), UNHEX(REPEAT(?, 32)), 'h1',
                        0, 0, 0, 0, UNHEX(REPEAT('55', 32)),
                        UTC_TIMESTAMP(6) + INTERVAL 2 MINUTE,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, intent.toString(), subject.toString(), journey.toString(),
                operation.toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), lookupDigestByte);
    }

    private void insertSubject(UUID id, String customerId) {
        jdbc.update("""
                INSERT INTO auth_customer
                (id, customer_id, customer_status_version, customer_last_block_version,
                 customer_status_checked_at, status, customer_security_version,
                 credential_security_version, policy_version, version, created_at, updated_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), ?, 1, 0, UTC_TIMESTAMP(6),
                        'ELIGIBLE', 0, 0, 'test-policy', 0, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, id.toString(), customerId);
    }

    private void insertDeviceBinding(UUID subjectId, String appId, String installation) {
        insertDeviceBinding(subjectId, appId, installation, "NONE");
    }

    private void insertDeviceBinding(UUID subjectId, String appId, String installation,
                                     String platformAssurance) {
        jdbc.update("""
                INSERT INTO auth_device_binding
                (id, subject_id, app_id, installation_hash, platform, label, status,
                 device_security_version, policy_version, possession_assurance,
                 platform_assurance, expires_at, version, created_at, updated_at)
                VALUES (UNHEX(REPLACE(?, '-', '')), UNHEX(REPLACE(?, '-', '')), ?,
                        UNHEX(SHA2(?, 256)), 'ANDROID', 'Test phone', 'PENDING_RESET',
                        0, 'test-policy', 'MFA_KEY_POSSESSION', ?,
                        UTC_TIMESTAMP(6) + INTERVAL 1 DAY, 0,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, UUID.randomUUID().toString(), subjectId.toString(), appId, installation,
                platformAssurance);
    }

}
