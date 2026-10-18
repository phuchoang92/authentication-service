package com.vpbank.dcp.infrastructure.persistence.schema;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import static org.assertj.core.api.Assertions.assertThat;

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

@Testcontainers
class RevocationCommandDigestMigrationIT {
    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(DockerImageName.parse(
            "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_revocation_digest")
            .withUsername("auth_test").withPassword("test-only-password");

    @Test
    void migrationPreservesAuditEventWithoutInventingACommandDigest() {
        assertThat(flyway(MigrationVersion.fromVersion("15")).migrate().migrationsExecuted)
                .isEqualTo(15);
        JdbcTemplate jdbc = new JdbcTemplate(new DriverManagerDataSource(
                MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword()));
        SubjectId subject = new SubjectId(UUID.randomUUID());
        UUID deviceId = UUID.randomUUID();
        UUID operationId = UUID.randomUUID();
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
                        'lookup-key', X'010203', 'data-key', 'ANDROID', 'Test', 'ACTIVE',
                        X'01020304', UNHEX(SHA2(?, 256)), 'ES256',
                        'NFC_FACE_SMS_OTP', 'test-policy', 'MFA_KEY_POSSESSION',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6) + INTERVAL 90 DAY,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, deviceId.toString(), subject.toString(), deviceId.toString(),
                "public-key-" + deviceId);
        jdbc.update("""
                INSERT INTO auth_security_audit_event
                  (id, auth_customer_id, channel, operation_id, event_sequence, event_type,
                   trusted_device_id, device_security_version, reason_code, actor_type, actor_id,
                   occurred_at, recorded_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), 'neo-mobile', UUID_TO_BIN(?), 1,
                        'DEVICE_REVOKED', UUID_TO_BIN(?), 1, 'CUSTOMER_REQUEST',
                        'CUSTOMER', 'customer-test',
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, UUID.randomUUID().toString(), subject.toString(),
                operationId.toString(), deviceId.toString());

        Flyway current = flyway(null);
        // V16 to V19: V18 drops the empty credential table without touching audit rows.
        assertThat(current.migrate().migrationsExecuted).isEqualTo(4);
        assertThat(jdbc.queryForObject("""
                SELECT command_digest FROM auth_security_audit_event
                 WHERE operation_id = UUID_TO_BIN(?)
                """, byte[].class, operationId.toString())).isNull();
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM auth_security_audit_event
                 WHERE operation_id = UUID_TO_BIN(?)
                """, Integer.class, operationId.toString())).isEqualTo(1);
        current.validate();
    }

    private Flyway flyway(MigrationVersion target) {
        var configuration = Flyway.configure()
                .dataSource(MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword());
        if (target != null) {
            configuration.target(target);
        }
        return configuration.load();
    }
}
