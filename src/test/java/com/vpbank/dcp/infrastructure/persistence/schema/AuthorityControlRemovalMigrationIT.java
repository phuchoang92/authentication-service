package com.vpbank.dcp.infrastructure.persistence.schema;

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

/** Proves the additive removal upgrades a populated V8 schema without touching login data. */
@Testcontainers
class AuthorityControlRemovalMigrationIT {
    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(DockerImageName.parse(
            "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_schema_upgrade")
            .withUsername("auth_test").withPassword("test-only-password");

    @Test
    void upgradesPopulatedV8AndPreservesCustomerDataAndMigrationChecksums() {
        Flyway previous = Flyway.configure()
                .dataSource(MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword())
                .target(MigrationVersion.fromVersion("8")).load();
        assertThat(previous.migrate().migrationsExecuted).isEqualTo(8);
        JdbcTemplate jdbc = new JdbcTemplate(new DriverManagerDataSource(
                MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword()));
        UUID subjectId = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO auth_customer
                  (id, customer_id, customer_status_version, customer_status_checked_at,
                   status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), 'customer-upgrade-test', 1, UTC_TIMESTAMP(6),
                        'ELIGIBLE', 'test-policy', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subjectId.toString());
        jdbc.update("""
                INSERT INTO auth_authority_control
                  (bank_scope, generation, redis_run_id, state, controller_id,
                   lease_until, fence, version, updated_at)
                VALUES ('bank-test-neo', UUID_TO_BIN(?), 'run-test', 'READY', UUID_TO_BIN(?),
                        UTC_TIMESTAMP(6) + INTERVAL 1 MINUTE, 7, 0, UTC_TIMESTAMP(6))
                """, UUID.randomUUID().toString(), UUID.randomUUID().toString());
        var originalChecksums = jdbc.queryForList("""
                SELECT version, checksum FROM flyway_schema_history
                 WHERE success = 1 ORDER BY installed_rank
                """);

        Flyway current = Flyway.configure()
                .dataSource(MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword()).load();
        assertThat(current.migrate().migrationsExecuted).isEqualTo(1);
        assertThat(current.info().current().getVersion()).isEqualTo(MigrationVersion.fromVersion("9"));
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'auth_authority_control'
                """, Integer.class)).isZero();
        assertThat(jdbc.queryForObject("""
                SELECT customer_id FROM auth_customer WHERE id = UUID_TO_BIN(?)
                """, String.class, subjectId.toString())).isEqualTo("customer-upgrade-test");
        assertThat(jdbc.queryForList("""
                SELECT version, checksum FROM flyway_schema_history
                 WHERE success = 1 AND version <> '9' ORDER BY installed_rank
                """)).isEqualTo(originalChecksums);
        current.validate();
        assertThat(current.migrate().migrationsExecuted).isZero();
    }
}
