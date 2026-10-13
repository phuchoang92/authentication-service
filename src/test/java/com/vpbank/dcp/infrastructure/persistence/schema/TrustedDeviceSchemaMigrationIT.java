package com.vpbank.dcp.infrastructure.persistence.schema;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/** Characterizes immutable V10; V12 tests assert the current schema without auth_customer_app. */
@Testcontainers
class TrustedDeviceSchemaMigrationIT {
    private static final DockerImageName MYSQL_IMAGE = DockerImageName.parse(
            "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242");

    @Container
    static final MySQLContainer<?> FRESH = new MySQLContainer<>(MYSQL_IMAGE)
            .withDatabaseName("auth_device_fresh")
            .withUsername("auth_test").withPassword("test-only-password");

    @Container
    static final MySQLContainer<?> POPULATED = new MySQLContainer<>(MYSQL_IMAGE)
            .withDatabaseName("auth_device_populated")
            .withUsername("auth_test").withPassword("test-only-password");

    @Test
    void createsTargetTablesOnFreshIsolatedDatabase() {
        Flyway flyway = Flyway.configure()
                .dataSource(FRESH.getJdbcUrl(), FRESH.getUsername(), FRESH.getPassword())
                .target(MigrationVersion.fromVersion("10")).load();

        assertThat(flyway.migrate().migrationsExecuted).isEqualTo(10);
        assertThat(flyway.info().current().getVersion()).isEqualTo(MigrationVersion.fromVersion("10"));
        JdbcTemplate jdbc = jdbc(FRESH);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE()
                   AND TABLE_NAME IN ('auth_customer_app', 'auth_trusted_device',
                                      'auth_device_push_registration', 'auth_biometric_login',
                                      'auth_security_audit_event')
                """, Integer.class)).isEqualTo(5);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM information_schema.COLUMNS
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'auth_trusted_device'
                   AND COLUMN_NAME IN ('device_id_lookup', 'device_id_ciphertext',
                                       'device_public_key', 'device_public_key_hash')
                """, Integer.class)).isEqualTo(4);
        assertThat(jdbc.queryForObject("""
                SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'auth_trusted_device'
                   AND COLUMN_NAME = 'device_id_ciphertext'
                """, Long.class)).isEqualTo(2048L);
        UUID customerA = UUID.randomUUID();
        UUID customerB = UUID.randomUUID();
        UUID deviceA = UUID.randomUUID();
        insertCustomerAndApp(jdbc, customerA, "customer-a");
        insertCustomerAndApp(jdbc, customerB, "customer-b");
        insertDevice(jdbc, customerA, deviceA);

        assertThatThrownBy(() -> jdbc.update("""
                UPDATE auth_customer_app SET primary_trusted_device_id = UUID_TO_BIN(?)
                 WHERE auth_customer_id = UUID_TO_BIN(?) AND app_id = 'neo-mobile'
                """, deviceA.toString(), customerB.toString()))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        jdbc.update("""
                UPDATE auth_customer_app SET primary_trusted_device_id = UUID_TO_BIN(?)
                 WHERE auth_customer_id = UUID_TO_BIN(?) AND app_id = 'neo-mobile'
                """, deviceA.toString(), customerA.toString());

        UUID revokeOperation = UUID.randomUUID();
        insertAudit(jdbc, customerA, deviceA, revokeOperation, 1, "DEVICE_REVOKED");
        assertThatThrownBy(() -> insertAudit(jdbc, customerA, deviceA,
                UUID.randomUUID(), 1, "DEVICE_REVOKED"))
                .isInstanceOf(org.springframework.dao.DuplicateKeyException.class);
        assertThatThrownBy(() -> insertAudit(jdbc, customerA, deviceA,
                revokeOperation, 1, "DEVICE_TRUSTED"))
                .isInstanceOf(org.springframework.dao.DuplicateKeyException.class);
        flyway.validate();
    }

    @Test
    void refusesPopulatedLegacyDatabaseWithoutInventingDeviceIdentity() {
        Flyway previous = Flyway.configure()
                .dataSource(POPULATED.getJdbcUrl(), POPULATED.getUsername(), POPULATED.getPassword())
                .target(MigrationVersion.fromVersion("9")).load();
        assertThat(previous.migrate().migrationsExecuted).isEqualTo(9);
        UUID customerId = UUID.randomUUID();
        jdbc(POPULATED).update("""
                INSERT INTO auth_customer
                  (id, customer_id, customer_status_version, customer_status_checked_at,
                   status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), 'legacy-customer', 1, UTC_TIMESTAMP(6),
                        'ELIGIBLE', 'test', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, customerId.toString());

        assertThatThrownBy(() -> flyway(POPULATED).migrate())
                .isInstanceOf(RuntimeException.class)
                .hasStackTraceContaining("ck_v10_empty_source");
        assertThat(jdbc(POPULATED).queryForObject("""
                SELECT COUNT(*) FROM auth_customer WHERE id = UUID_TO_BIN(?)
                """, Integer.class, customerId.toString())).isEqualTo(1);
        assertThat(jdbc(POPULATED).queryForObject("""
                SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'auth_trusted_device'
                """, Integer.class)).isZero();
    }

    private static Flyway flyway(MySQLContainer<?> mysql) {
        return Flyway.configure().dataSource(mysql.getJdbcUrl(), mysql.getUsername(), mysql.getPassword()).load();
    }

    private static JdbcTemplate jdbc(MySQLContainer<?> mysql) {
        return new JdbcTemplate(new DriverManagerDataSource(
                mysql.getJdbcUrl(), mysql.getUsername(), mysql.getPassword()));
    }

    private static void insertCustomerAndApp(JdbcTemplate jdbc, UUID customerId, String businessId) {
        jdbc.update("""
                INSERT INTO auth_customer
                  (id, customer_id, customer_status_version, customer_status_checked_at,
                   status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), ?, 1, UTC_TIMESTAMP(6), 'ELIGIBLE', 'test',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, customerId.toString(), businessId);
        jdbc.update("""
                INSERT INTO auth_customer_app
                  (auth_customer_id, app_id, status, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), 'neo-mobile', 'ACTIVE', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, customerId.toString());
    }

    private static void insertDevice(JdbcTemplate jdbc, UUID customerId, UUID deviceId) {
        jdbc.update("""
                INSERT INTO auth_trusted_device
                  (id, auth_customer_id, app_id, device_id_lookup, device_id_lookup_key_id,
                   device_id_ciphertext, device_id_key_id, platform, label, status,
                   device_public_key, device_public_key_hash, device_key_algorithm,
                   trust_method, trust_policy_version, possession_assurance,
                   trusted_at, expires_at, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), 'neo-mobile', UNHEX(REPEAT('11', 32)),
                        'test-lookup-key', X'010203', 'test-encryption-key', 'ANDROID',
                        'Test device', 'ACTIVE', X'01020304', UNHEX(REPEAT('22', 32)),
                        'ES256', 'NFC_FACE_SMS_OTP', 'test-policy', 'MFA_KEY_POSSESSION',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6) + INTERVAL 90 DAY,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, deviceId.toString(), customerId.toString());
    }

    private static void insertAudit(JdbcTemplate jdbc, UUID customerId, UUID deviceId,
                                    UUID operationId, int sequence, String eventType) {
        jdbc.update("""
                INSERT INTO auth_security_audit_event
                  (id, auth_customer_id, app_id, operation_id, event_sequence, event_type,
                   trusted_device_id, device_security_version, reason_code, actor_type,
                   actor_id, occurred_at, recorded_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), 'neo-mobile', UUID_TO_BIN(?), ?, ?,
                        UUID_TO_BIN(?), 1, 'CUSTOMER_REQUEST', 'CUSTOMER', 'test-actor',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, UUID.randomUUID().toString(), customerId.toString(),
                operationId.toString(), sequence, eventType, deviceId.toString());
    }
}
