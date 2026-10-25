package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.model.CustomerAuthentication;
import com.vpbank.dcp.auth.domain.enums.PasswordStatus;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.LockoutPolicy;
import com.vpbank.dcp.auth.domain.model.PasswordLockout;
import com.vpbank.dcp.auth.domain.model.UserName;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.infrastructure.config.JpaConfiguration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** Phase-2 columns on real MySQL: existing rows default to ACTIVE/0, lockout writes are compare-and-set. */
@Testcontainers
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=validate", "spring.flyway.enabled=true"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(JpaConfiguration.class)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class CustomerAuthenticationPersistenceAdapterIT {
    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.4");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @Autowired CustomerAuthenticationJpaRepository rows;
    @Autowired JdbcClient jdbc;
    private CustomerAuthenticationPersistenceAdapter identities;
    private final Instant now = Instant.parse("2026-10-25T10:00:00.123Z");

    @BeforeEach
    void seed() {
        identities = new CustomerAuthenticationPersistenceAdapter(rows);
        rows.deleteAll();
        // A phase-1 row: the phase-2 columns take their defaults.
        jdbc.sql("""
                INSERT INTO CUSTOMER_AUTHENTICATION (CUSTOMER_ID, USER_NAME, IDENTITY_ISSUER, IDENTITY_SUBJECT,
                    STATUS, CREATED_AT, UPDATED_AT) VALUES ('90359', 'Alice', 'iss', 'sub-1', 'ACTIVE', NOW(6), NOW(6))""")
                .update();
    }

    @Test
    void readsCaseInsensitivelyWithDefaultLockout() {
        CustomerAuthentication alice = identities.findByUserName(new UserName("ALICE")).orElseThrow();
        assertThat(alice.customerId()).isEqualTo(new CustomerId("90359"));
        assertThat(alice.lockout()).isEqualTo(PasswordLockout.none());
        assertThat(alice.version()).isZero();
        assertThat(identities.findByUserName(new UserName("bob"))).isEmpty();
    }

    @Test
    void lockoutWritesAreCompareAndSetAndKeepStatusAndTimeTogether() {
        CustomerAuthentication alice = identities.findByUserName(new UserName("alice")).orElseThrow();
        PasswordLockout locked = PasswordLockout.none().afterFailure(now, LockoutPolicy.standard())
                .afterFailure(now, LockoutPolicy.standard()).afterFailure(now, LockoutPolicy.standard());

        CustomerAuthentication saved = identities.saveLockoutIfCurrent(alice, locked).orElseThrow();
        assertThat(saved.version()).isEqualTo(1);
        assertThat(saved.lockout().status()).isEqualTo(PasswordStatus.LOCKED);
        assertThat(saved.lockout().lockedUntil()).isEqualTo(now.plus(15, ChronoUnit.MINUTES));
        assertThat(jdbc.sql("SELECT PASSWORD_FAILED_COUNT FROM CUSTOMER_AUTHENTICATION").query(Integer.class).single())
                .isEqualTo(3);

        // The stale reader (version 0) loses; the current one wins.
        assertThat(identities.saveLockoutIfCurrent(alice, locked.afterFailure(now, LockoutPolicy.standard()))).isEmpty();
        assertThat(identities.saveLockoutIfCurrent(saved, PasswordLockout.none())).isPresent();
        assertThat(identities.findByUserName(new UserName("alice")).orElseThrow().lockout()).isEqualTo(PasswordLockout.none());
    }

    @Test
    void unlockResetsEverythingAndReportsUnknownCustomers() {
        CustomerAuthentication alice = identities.findByUserName(new UserName("alice")).orElseThrow();
        identities.saveLockoutIfCurrent(alice, new PasswordLockout(PasswordStatus.PERMANENTLY_LOCKED, 5, null));

        assertThat(identities.unlock(new CustomerId("90359"))).isTrue();
        assertThat(identities.findByUserName(new UserName("alice")).orElseThrow().lockout()).isEqualTo(PasswordLockout.none());
        assertThat(identities.unlock(new CustomerId("00000"))).isFalse();
    }
}
