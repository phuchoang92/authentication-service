package com.vpbank.dcp.infrastructure.persistence.schema;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Set;
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
class RetiredLoginStorageMigrationIT {
    private static final DockerImageName MYSQL_IMAGE = DockerImageName.parse(
            "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242");

    @Container
    static final MySQLContainer<?> FRESH = new MySQLContainer<>(MYSQL_IMAGE)
            .withDatabaseName("auth_retired_fresh")
            .withUsername("auth_test").withPassword("test-only-password");

    @Container
    static final MySQLContainer<?> POPULATED = new MySQLContainer<>(MYSQL_IMAGE)
            .withDatabaseName("auth_retired_populated")
            .withUsername("auth_test").withPassword("test-only-password");

    @Container
    static final MySQLContainer<?> POPULATED_DEVICE = new MySQLContainer<>(MYSQL_IMAGE)
            .withDatabaseName("auth_device_channel_populated")
            .withUsername("auth_test").withPassword("test-only-password");

    @Test
    void freshDatabaseRetainsOnlyCurrentCustomerAndDeviceTables() {
        Flyway flyway = flyway(FRESH);
        assertThat(flyway.migrate().migrationsExecuted).isEqualTo(17);

        JdbcTemplate jdbc = jdbc(FRESH);
        Set<String> tables = Set.copyOf(jdbc.queryForList("""
                SELECT TABLE_NAME FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE 'auth_%'
                """, String.class));
        assertThat(tables).containsExactlyInAnyOrder(
                "auth_customer", "auth_trusted_device",
                "auth_device_push_registration", "auth_biometric_login",
                "auth_security_audit_event", "auth_device_credential", "auth_device_trust_reset");
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM information_schema.COLUMNS
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'auth_trusted_device'
                   AND COLUMN_NAME IN ('channel', 'is_primary', 'primary_slot')
                """, Integer.class)).isEqualTo(3);
        flyway.validate();
    }

    @Test
    void populatedCustomerAppStopsChannelMigrationBeforeSchemaChanges() {
        Flyway before = Flyway.configure()
                .dataSource(POPULATED_DEVICE.getJdbcUrl(), POPULATED_DEVICE.getUsername(),
                        POPULATED_DEVICE.getPassword())
                .target(MigrationVersion.fromVersion("11")).load();
        assertThat(before.migrate().migrationsExecuted).isEqualTo(11);
        JdbcTemplate jdbc = jdbc(POPULATED_DEVICE);
        String customerId = "00000000-0000-0000-0000-000000000011";
        jdbc.update("""
                INSERT INTO auth_customer
                    (id, customer_id, customer_status_version, customer_status_checked_at,
                     status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), 'test-device-channel', 1, UTC_TIMESTAMP(6),
                        'ELIGIBLE', 'test', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, customerId);
        jdbc.update("""
                INSERT INTO auth_customer_app
                    (auth_customer_id, app_id, status, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), 'neo-mobile', 'ACTIVE', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, customerId);

        assertThatThrownBy(() -> flyway(POPULATED_DEVICE).migrate())
                .isInstanceOf(RuntimeException.class)
                .hasStackTraceContaining("ck_v12_empty_device_state");
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'auth_customer_app'
                """, Integer.class)).isEqualTo(1);
    }

    @Test
    void populatedOldTableStopsBeforeAnyDrop() {
        Flyway before = Flyway.configure()
                .dataSource(POPULATED.getJdbcUrl(), POPULATED.getUsername(), POPULATED.getPassword())
                .target(MigrationVersion.fromVersion("10")).load();
        assertThat(before.migrate().migrationsExecuted).isEqualTo(10);
        JdbcTemplate jdbc = jdbc(POPULATED);
        jdbc.update("""
                INSERT INTO auth_customer
                    (id, customer_id, customer_status_version, customer_status_checked_at,
                     status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), 'test-customer', 1, UTC_TIMESTAMP(6),
                        'ELIGIBLE', 'test', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, "00000000-0000-0000-0000-000000000001");
        jdbc.update("""
                INSERT INTO auth_subject_app
                    (subject_id, app_id, status, version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), 'neo-mobile', 'ACTIVE', 0,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, "00000000-0000-0000-0000-000000000001");

        assertThatThrownBy(() -> flyway(POPULATED).migrate())
                .isInstanceOf(RuntimeException.class)
                .hasStackTraceContaining("ck_v11_empty_source");
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'auth_operation'
                """, Integer.class)).isEqualTo(1);
    }

    private static Flyway flyway(MySQLContainer<?> mysql) {
        return Flyway.configure().dataSource(mysql.getJdbcUrl(), mysql.getUsername(), mysql.getPassword()).load();
    }

    private static JdbcTemplate jdbc(MySQLContainer<?> mysql) {
        return new JdbcTemplate(new DriverManagerDataSource(
                mysql.getJdbcUrl(), mysql.getUsername(), mysql.getPassword()));
    }
}
