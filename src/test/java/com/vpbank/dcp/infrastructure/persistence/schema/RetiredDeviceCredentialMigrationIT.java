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

/** V18 must never drop stored factor secrets: a populated table stops the migration. */
@Testcontainers
class RetiredDeviceCredentialMigrationIT {
    private static final DockerImageName MYSQL_IMAGE = DockerImageName.parse(
            "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242");

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(MYSQL_IMAGE)
            .withDatabaseName("auth_credential_populated")
            .withUsername("auth_test").withPassword("test-only-password");

    @Test
    void populatedCredentialTableStopsV18BeforeTheDrop() {
        Flyway before = Flyway.configure()
                .dataSource(MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword())
                .target(MigrationVersion.fromVersion("17")).load();
        assertThat(before.migrate().migrationsExecuted).isEqualTo(17);
        JdbcTemplate jdbc = new JdbcTemplate(new DriverManagerDataSource(
                MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword()));
        UUID customerId = UUID.randomUUID();
        UUID bindingId = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO auth_customer
                  (id, customer_id, customer_status_version, customer_status_checked_at,
                   status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), ?, 1, UTC_TIMESTAMP(6), 'ELIGIBLE', 'test',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, customerId.toString(), "customer-" + customerId);
        jdbc.update("""
                INSERT INTO auth_trusted_device
                  (id, auth_customer_id, channel, device_id_lookup, device_id_lookup_key_id,
                   device_id_ciphertext, device_id_key_id, platform, label, status,
                   device_public_key, device_public_key_hash, device_key_algorithm,
                   trust_method, trust_policy_version, possession_assurance,
                   trusted_at, expires_at, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), 'neo-mobile', UNHEX(SHA2(?, 256)),
                        'test-lookup-key', X'010203', 'test-encryption-key', 'ANDROID',
                        'Test device', 'ACTIVE', X'01020304', UNHEX(SHA2(?, 256)),
                        'ES256', 'NFC_FACE_SMS_OTP', 'test-policy', 'MFA_KEY_POSSESSION',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6) + INTERVAL 90 DAY,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, bindingId.toString(), customerId.toString(),
                "installation-" + bindingId, "public-key-" + bindingId);
        jdbc.update("""
                INSERT INTO auth_device_credential
                  (id, trusted_device_id, secret_ciphertext, secret_key_id, status,
                   activated_at, failed_attempts)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), X'01020304', 'test-key', 'ACTIVE',
                        UTC_TIMESTAMP(6), 0)
                """, UUID.randomUUID().toString(), bindingId.toString());

        Flyway latest = Flyway.configure()
                .dataSource(MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword()).load();
        assertThatThrownBy(latest::migrate)
                .isInstanceOf(RuntimeException.class)
                .hasStackTraceContaining("ck_v18_empty_credential");
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM auth_device_credential", Integer.class)).isEqualTo(1);
    }
}
