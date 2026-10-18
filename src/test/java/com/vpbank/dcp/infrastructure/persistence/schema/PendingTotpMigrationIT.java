package com.vpbank.dcp.infrastructure.persistence.schema;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@Testcontainers
class PendingTotpMigrationIT {
    private static final DockerImageName MYSQL_IMAGE = DockerImageName.parse(
            "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242");

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(MYSQL_IMAGE)
            .withDatabaseName("auth_pending_totp")
            .withUsername("auth_test").withPassword("test-only-password");

    @Test
    void pendingEnrollmentRequiresExpiryAndOccupiesCurrentCredentialSlot() {
        Flyway flyway = Flyway.configure()
                .dataSource(MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword())
                .load();
        assertThat(flyway.migrate().migrationsExecuted).isEqualTo(17);
        JdbcTemplate jdbc = new JdbcTemplate(new DriverManagerDataSource(
                MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword()));
        SubjectId subject = new SubjectId(UUID.randomUUID());
        BindingId bindingId = new BindingId(UUID.randomUUID());
        jdbc.update("""
                INSERT INTO auth_customer
                  (id, customer_id, customer_status_version, customer_status_checked_at,
                   status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), ?, 1, UTC_TIMESTAMP(6), 'ELIGIBLE', 'test',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subject.toString(), "customer-" + subject);
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
                """, bindingId.toString(), subject.toString(),
                "installation-" + bindingId, "public-key-" + bindingId);
        jdbc.update("""
                INSERT INTO auth_device_credential
                  (id, trusted_device_id, secret_ciphertext, secret_key_id, status,
                   public_credential_id, public_enrollment_id, enrollment_expires_at,
                   recipient_public_jwk)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), X'010203', 'test-key', 'PENDING',
                        ?, ?, UTC_TIMESTAMP(6) + INTERVAL 5 MINUTE, ?)
                """, UUID.randomUUID().toString(), bindingId.toString(),
                "credential-opaque-1234567890", "enrollment-opaque-1234567890", "test-public-jwk");
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO auth_device_credential
                  (id, trusted_device_id, secret_ciphertext, secret_key_id, status, activated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), X'010203', 'test-key', 'ACTIVE',
                        UTC_TIMESTAMP(6))
                """, UUID.randomUUID().toString(), bindingId.toString()))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM auth_device_credential
                WHERE trusted_device_id = UUID_TO_BIN(?) AND status = 'PENDING'
                """, Integer.class, bindingId.toString())).isEqualTo(1);
        flyway.validate();
    }
}
