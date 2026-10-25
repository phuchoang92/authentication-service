package com.vpbank.dcp.auth.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.core.customer.Registration;
import com.vpbank.dcp.auth.core.customer.RegistrationState;
import com.vpbank.dcp.auth.core.customer.RegistrationStore.CompleteResult;
import com.vpbank.dcp.auth.core.customer.RegistrationStore.ReserveResult;
import com.vpbank.dcp.auth.core.customer.RequestDigest;
import com.zaxxer.hikari.HikariDataSource;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** The store against real MySQL 8.4 with the Flyway V1 schema, including its unique keys. */
@Testcontainers
class JdbcRegistrationStoreIT {
    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.4");

    private static HikariDataSource dataSource;
    private static JdbcClient jdbc;
    private JdbcRegistrationStore store;
    private final Instant now = Instant.parse("2026-10-25T03:00:00.123456Z");
    private final Instant expires = now.plus(1, ChronoUnit.DAYS);

    @BeforeAll
    static void migrate() {
        dataSource = new HikariDataSource();
        dataSource.setJdbcUrl(MYSQL.getJdbcUrl());
        dataSource.setUsername(MYSQL.getUsername());
        dataSource.setPassword(MYSQL.getPassword());
        Flyway.configure().dataSource(dataSource).load().migrate();
        jdbc = JdbcClient.create(dataSource);
    }

    @AfterAll
    static void close() {
        dataSource.close();
    }

    @BeforeEach
    void clean() {
        jdbc.sql("DELETE FROM CUSTOMER_AUTHENTICATION_REGISTRATION").update();
        jdbc.sql("DELETE FROM CUSTOMER_AUTHENTICATION").update();
        store = new JdbcRegistrationStore(jdbc,
                new TransactionTemplate(new DataSourceTransactionManager(dataSource)));
    }

    @Test
    void walksEveryStepToReadyAndWritesTheIdentity() {
        UUID id = UUID.randomUUID();
        Registration reserved = reserved(store.reserve(id, "90359", "alice", digest(1), expires, now));
        assertThat(reserved.state()).isEqualTo(RegistrationState.RESERVED);

        assertThat(store.markUserCreated(id, 0, "https://kc/realms/test", "sub-1", now)).isTrue();
        assertThat(store.markSmsAccepted(id, 1, now)).isTrue();
        assertThat(store.complete(id, 2, now)).isEqualTo(CompleteResult.COMPLETED);

        Registration ready = store.findLatest("90359").orElseThrow();
        assertThat(ready.state()).isEqualTo(RegistrationState.READY);
        assertThat(ready.version()).isEqualTo(3);
        assertThat(ready.identitySubject()).isEqualTo("sub-1");
        assertThat(ready.requestDigest()).isEqualTo(digest(1));
        assertThat(ready.expiresAt()).isEqualTo(expires);
        assertThat(jdbc.sql("SELECT USER_NAME FROM CUSTOMER_AUTHENTICATION WHERE CUSTOMER_ID = '90359'")
                .query(String.class).single()).isEqualTo("alice");
    }

    @Test
    void aSecondOpenRequestForTheSameCustomerReturnsTheFirst() {
        UUID first = UUID.randomUUID();
        store.reserve(first, "90359", "alice", digest(1), expires, now);

        ReserveResult again = store.reserve(UUID.randomUUID(), "90359", "alice2", digest(2), expires, now);

        assertThat(again).isInstanceOf(ReserveResult.CustomerHasOpen.class);
        assertThat(((ReserveResult.CustomerHasOpen) again).existing().requestId()).isEqualTo(first);
    }

    @Test
    void anOpenUsernameCannotBeReservedTwiceEvenWithOtherCase() {
        store.reserve(UUID.randomUUID(), "90359", "alice", digest(1), expires, now);

        assertThat(store.reserve(UUID.randomUUID(), "77777", "ALICE", digest(2), expires, now))
                .isInstanceOf(ReserveResult.UserNameTaken.class);
    }

    @Test
    void aFailedRequestFreesTheSlot() {
        UUID first = UUID.randomUUID();
        store.reserve(first, "90359", "alice", digest(1), expires, now);
        assertThat(store.markFailed(first, 0, now)).isTrue();

        UUID second = UUID.randomUUID();
        assertThat(store.reserve(second, "90359", "alice", digest(1), expires, now.plusSeconds(1)))
                .isInstanceOf(ReserveResult.Reserved.class);
        assertThat(store.findLatest("90359").orElseThrow().requestId()).isEqualTo(second);
    }

    @Test
    void aStepRunsOnlyFromTheExpectedVersionAndState() {
        UUID id = UUID.randomUUID();
        store.reserve(id, "90359", "alice", digest(1), expires, now);

        assertThat(store.markUserCreated(id, 7, "iss", "sub", now)).isFalse();
        assertThat(store.markSmsAccepted(id, 0, now)).isFalse();
        assertThat(store.complete(id, 0, now)).isEqualTo(CompleteResult.STALE);
        assertThat(store.findLatest("90359").orElseThrow().state()).isEqualTo(RegistrationState.RESERVED);
    }

    @Test
    void completeChangesNothingWhenTheUsernameAlreadyBelongsToSomeone() {
        jdbc.sql("""
                INSERT INTO CUSTOMER_AUTHENTICATION (CUSTOMER_ID, USER_NAME, IDENTITY_ISSUER,
                    IDENTITY_SUBJECT, STATUS, CREATED_AT, UPDATED_AT)
                VALUES ('11111', 'Alice', 'iss', 'other-sub', 'ACTIVE', NOW(6), NOW(6))""").update();
        UUID id = UUID.randomUUID();
        store.reserve(id, "90359", "alice", digest(1), expires, now);
        store.markUserCreated(id, 0, "iss", "sub-1", now);
        store.markSmsAccepted(id, 1, now);

        assertThat(store.complete(id, 2, now)).isEqualTo(CompleteResult.IDENTITY_TAKEN);
        assertThat(store.findLatest("90359").orElseThrow().state())
                .isEqualTo(RegistrationState.SMS_ACCEPTED);
        assertThat(jdbc.sql("SELECT COUNT(*) FROM CUSTOMER_AUTHENTICATION").query(Long.class).single())
                .isEqualTo(1L);
    }

    private static Registration reserved(ReserveResult result) {
        assertThat(result).isInstanceOf(ReserveResult.Reserved.class);
        return ((ReserveResult.Reserved) result).registration();
    }

    private static RequestDigest digest(int fill) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) fill);
        return new RequestDigest(bytes);
    }
}
