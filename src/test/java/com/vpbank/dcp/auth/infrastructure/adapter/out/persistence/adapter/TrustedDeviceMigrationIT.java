package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class TrustedDeviceMigrationIT {
    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.4");

    @Test
    void preservesCurrentBindingsAndMovesLegacyPendingAndRevokedRows() {
        DriverManagerDataSource dataSource =
                new DriverManagerDataSource(MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword());
        Flyway.configure().dataSource(dataSource).target("7").load().migrate();
        JdbcClient jdbc = JdbcClient.create(dataSource);
        seedBindings(jdbc);
        seedApprovals(jdbc);

        Flyway.configure().dataSource(dataSource).load().migrate();

        assertThat(jdbc.sql("SELECT HEX(ID) FROM TRUSTED_DEVICE").query(String.class).list())
                .containsExactly("00000000000000000000000000000001");
        assertThat(jdbc.sql("SELECT PRIMARY_DEVICE_ID FROM PRIMARY_TRUSTED_DEVICE").query(byte[].class).optional())
                .isEmpty();
        assertThat(jdbc.sql("SELECT HEX(ID) FROM TRUSTED_DEVICE_REVOKE").query(String.class).list())
                .containsExactly("00000000000000000000000000000004");
        assertThat(jdbc.sql("SELECT PRIMARY_PUBLIC_KEY FROM TRUSTED_DEVICE_REVOKE").query(String.class).single())
                .isEqualTo("{old-revoked-key}");
        assertThat(jdbc.sql("SELECT EVENT_TYPE FROM TRUSTED_DEVICE_AUDIT").query(String.class).list())
                .containsExactly("DEVICE_EXPIRED");
        assertThat(jdbc.sql("""
                SELECT CANDIDATE_PUBLIC_KEY FROM TRUSTED_DEVICE_ENROLLMENT WHERE STATE = 'WAITING_APPROVAL'
                """).query(String.class).list()).containsExactly("{pending-key}");
        assertThat(jdbc.sql("""
                SELECT HEX(REQUESTER_CLIENT_DEVICE_ID_CIPHERTEXT) FROM TRUSTED_DEVICE_ENROLLMENT
                WHERE STATE = 'WAITING_APPROVAL' AND TARGET_DEVICE_ID IS NULL
                """).query(String.class).list()).containsExactly("02");
        assertThat(jdbc.sql("""
                SELECT STATE FROM TRUSTED_DEVICE_ENROLLMENT ORDER BY ID
                """).query(String.class).list()).containsExactly("FAILED", "WAITING_APPROVAL", "EXPIRED");
        assertThatThrownBy(() -> jdbc.sql("""
                INSERT INTO TRUSTED_DEVICE
                    (ID, CUSTOMER_ID, CHANNEL, CLIENT_DEVICE_ID_LOOKUP, CLIENT_DEVICE_ID_LOOKUP_KEY_ID,
                     CLIENT_DEVICE_ID_CIPHERTEXT, CLIENT_DEVICE_ID_KEY_ID, PLATFORM, STATUS, TRUST_LEVEL, TRUSTED_AT,
                     EXPIRES_AT, CREATED_AT, UPDATED_AT)
                SELECT UNHEX(LPAD('5',32,'0')), CUSTOMER_ID, CHANNEL, CLIENT_DEVICE_ID_LOOKUP, CLIENT_DEVICE_ID_LOOKUP_KEY_ID,
                     CLIENT_DEVICE_ID_CIPHERTEXT, CLIENT_DEVICE_ID_KEY_ID, PLATFORM, STATUS, TRUST_LEVEL, TRUSTED_AT,
                     EXPIRES_AT, CREATED_AT, UPDATED_AT
                FROM TRUSTED_DEVICE
                """).update()).isInstanceOf(DataIntegrityViolationException.class);
    }

    private static void seedBindings(JdbcClient jdbc) {
        jdbc.sql("""
                INSERT INTO TRUSTED_DEVICE
                    (ID, CUSTOMER_ID, CHANNEL, CLIENT_DEVICE_ID_LOOKUP, CLIENT_DEVICE_ID_LOOKUP_KEY_ID,
                     CLIENT_DEVICE_ID_CIPHERTEXT, CLIENT_DEVICE_ID_KEY_ID, PLATFORM, STATUS, TRUST_LEVEL, TRUSTED_AT,
                     EXPIRES_AT, PRIMARY_PUBLIC_KEY, CREATED_AT, UPDATED_AT)
                VALUES
                    (UNHEX(LPAD('1',32,'0')), '90359', 'MOBILE', UNHEX(LPAD('1',64,'0')), 'd1',
                     X'01', 'e1', 'ANDROID', 'ACTIVE', 'TRUSTED', UTC_TIMESTAMP(),
                     UTC_TIMESTAMP() + INTERVAL 1 DAY, '{active-key}', UTC_TIMESTAMP(), UTC_TIMESTAMP()),
                    (UNHEX(LPAD('2',32,'0')), '90359', 'MOBILE', UNHEX(LPAD('2',64,'0')), 'd1',
                     X'02', 'e1', 'IOS', 'PENDING', 'NONE', NULL,
                     UTC_TIMESTAMP() + INTERVAL 1 DAY, '{pending-key}', UTC_TIMESTAMP(), UTC_TIMESTAMP()),
                    (UNHEX(LPAD('3',32,'0')), '90359', 'MOBILE', UNHEX(LPAD('1',64,'0')), 'd1',
                     X'03', 'e1', 'ANDROID', 'EXPIRED', 'TRUSTED', UTC_TIMESTAMP() - INTERVAL 180 DAY,
                     UTC_TIMESTAMP() - INTERVAL 1 DAY, '{old-expired-key}', UTC_TIMESTAMP(), UTC_TIMESTAMP()),
                    (UNHEX(LPAD('4',32,'0')), '90359', 'MOBILE', UNHEX(LPAD('1',64,'0')), 'd1',
                     X'04', 'e1', 'ANDROID', 'REVOKED', 'TRUSTED', UTC_TIMESTAMP(),
                     UTC_TIMESTAMP() + INTERVAL 1 DAY, '{old-revoked-key}', UTC_TIMESTAMP(), UTC_TIMESTAMP())
                """).update();
        jdbc.sql("""
                INSERT INTO PRIMARY_TRUSTED_DEVICE
                    (CUSTOMER_ID, CHANNEL, PRIMARY_DEVICE_ID, ASSIGNED_AT, CREATED_AT, UPDATED_AT)
                VALUES ('90359', 'MOBILE', UNHEX(LPAD('4',32,'0')), UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())
                """).update();
        jdbc.sql("""
                INSERT INTO TRUSTED_DEVICE_AUDIT
                    (ID, CUSTOMER_ID, CORRELATION_ID, EVENT_SEQUENCE, EVENT_TYPE, CAUSE, ACTOR_TYPE, ACTOR_SUBJECT,
                     TARGET_DEVICE_ID, REASON_CODE, POLICY_VERSION, OCCURRED_AT)
                VALUES (UNHEX(LPAD('3',32,'0')), '90359', 'legacy-expiry', 0, 'DEVICE_EXPIRED', 'POLICY',
                    'CUSTOMER', '90359', UNHEX(LPAD('3',32,'0')), 'DEVICE_CAP', 'td-p3-v1', UTC_TIMESTAMP())
                """).update();
    }

    private static void seedApprovals(JdbcClient jdbc) {
        jdbc.sql("""
                INSERT INTO TRUSTED_DEVICE_ENROLLMENT
                    (ID, CUSTOMER_ID, CHANNEL, PURPOSE, STATE, TARGET_DEVICE_ID, REQUESTER_CLIENT_DEVICE_ID_LOOKUP,
                     CLIENT_DEVICE_ID_LOOKUP_KEY_ID, EXPIRES_AT, CREATION_IDEMPOTENCY_DIGEST, CREATED_AT, UPDATED_AT)
                VALUES
                    (UNHEX(LPAD('a1',32,'0')), '90359', 'MOBILE', 'TRUST_DEVICE_APPROVAL', 'WAITING_APPROVAL',
                     UNHEX(LPAD('2',32,'0')), UNHEX(LPAD('2',64,'0')), 'd1', UTC_TIMESTAMP() + INTERVAL 1 DAY,
                     UNHEX(LPAD('a1',64,'0')), UTC_TIMESTAMP() - INTERVAL 1 MINUTE, UTC_TIMESTAMP()),
                    (UNHEX(LPAD('a2',32,'0')), '90359', 'MOBILE', 'TRUST_DEVICE_APPROVAL', 'WAITING_APPROVAL',
                     UNHEX(LPAD('2',32,'0')), UNHEX(LPAD('2',64,'0')), 'd1', UTC_TIMESTAMP() + INTERVAL 1 DAY,
                     UNHEX(LPAD('a2',64,'0')), UTC_TIMESTAMP(), UTC_TIMESTAMP()),
                    (UNHEX(LPAD('a3',32,'0')), '90359', 'MOBILE', 'TRUST_DEVICE_APPROVAL', 'WAITING_APPROVAL',
                     UNHEX(LPAD('2',32,'0')), UNHEX(LPAD('2',64,'0')), 'd1', UTC_TIMESTAMP() - INTERVAL 1 DAY,
                     UNHEX(LPAD('a3',64,'0')), UTC_TIMESTAMP(), UTC_TIMESTAMP())
                """).update();
    }
}
