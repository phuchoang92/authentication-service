package com.vpbank.dcp.auth.adapter.out.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.RegistrationJpaRepository;
import com.vpbank.dcp.auth.application.port.out.RegistrationRepository;
import com.vpbank.dcp.auth.application.port.out.RegistrationRepository.CompleteResult;
import com.vpbank.dcp.auth.application.port.out.RegistrationRepository.ReserveResult;
import com.vpbank.dcp.auth.config.JpaConfiguration;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.Registration;
import com.vpbank.dcp.auth.domain.model.RegistrationId;
import com.vpbank.dcp.auth.domain.model.RegistrationState;
import com.vpbank.dcp.auth.domain.model.RequestDigest;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
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

/**
 * The JPA adapter against real MySQL 8.4 with the Flyway V1 schema: entity validation, unique
 * keys, compare-and-set and the two-table completion. No test transaction, so every repository
 * call commits like in production.
 */
@Testcontainers
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=validate", "spring.flyway.enabled=true"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(JpaConfiguration.class)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class RegistrationPersistenceAdapterIT {
    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.4");
    private static final CustomerId CUSTOMER = new CustomerId("90359");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @Autowired RegistrationRepository store;
    @Autowired RegistrationJpaRepository registrations;
    @Autowired CustomerAuthenticationJpaRepository identities;
    @Autowired JdbcClient jdbc;
    private final Instant expires = Instant.parse("2026-10-26T03:00:00.123456Z");

    @BeforeEach
    void clean() {
        registrations.deleteAll();
        identities.deleteAll();
    }

    @Test
    void walksEveryStepToReadyAndWritesTheIdentity() {
        Registration reserved = reserved(store.reserve(fresh(CUSTOMER, "alice", 1)));
        assertThat(reserved.state()).isEqualTo(RegistrationState.RESERVED);

        Registration userCreated = store.save(reserved.markUserCreated("https://kc/realms/test", "sub-1")).orElseThrow();
        Registration smsAccepted = store.save(userCreated.markSmsAccepted()).orElseThrow();
        assertThat(store.complete(smsAccepted.complete())).isEqualTo(CompleteResult.COMPLETED);

        Registration ready = store.findLatest(CUSTOMER).orElseThrow();
        assertThat(ready.state()).isEqualTo(RegistrationState.READY);
        assertThat(ready.version()).isEqualTo(3);
        assertThat(ready.identitySubject()).isEqualTo("sub-1");
        assertThat(ready.requestDigest()).isEqualTo(digest(1));
        assertThat(ready.expiresAt()).isEqualTo(expires);
        assertThat(identities.findById("90359").orElseThrow().getUserName()).isEqualTo("alice");
        assertThat(jdbc.sql("SELECT OPEN_SLOT FROM CUSTOMER_AUTHENTICATION_REGISTRATION").query(Integer.class)
                .optional()).isEmpty();
    }

    @Test
    void aSecondOpenRequestForTheSameCustomerReturnsTheFirst() {
        Registration first = reserved(store.reserve(fresh(CUSTOMER, "alice", 1)));

        ReserveResult again = store.reserve(fresh(CUSTOMER, "alice2", 2));

        assertThat(again).isInstanceOf(ReserveResult.CustomerHasOpen.class);
        assertThat(((ReserveResult.CustomerHasOpen) again).existing().id()).isEqualTo(first.id());
    }

    @Test
    void anOpenUsernameCannotBeReservedTwiceEvenWithOtherCase() {
        store.reserve(fresh(CUSTOMER, "alice", 1));

        assertThat(store.reserve(fresh(new CustomerId("77777"), "ALICE", 2)))
                .isInstanceOf(ReserveResult.UserNameTaken.class);
    }

    @Test
    void aFailedRequestFreesTheSlot() {
        Registration first = reserved(store.reserve(fresh(CUSTOMER, "alice", 1)));
        assertThat(store.save(first.fail())).isPresent();

        Registration second = reserved(store.reserve(fresh(CUSTOMER, "alice", 1)));
        assertThat(store.findLatest(CUSTOMER).orElseThrow().id()).isEqualTo(second.id());
    }

    @Test
    void aStepIsSavedOnlyFromTheVersionStillStored() {
        Registration reserved = reserved(store.reserve(fresh(CUSTOMER, "alice", 1)));

        assertThat(store.save(reserved.withVersion(7).markUserCreated("iss", "sub"))).isEmpty();
        assertThat(store.complete(reserved.markUserCreated("iss", "sub").markSmsAccepted().complete()))
                .isEqualTo(CompleteResult.STALE);
        assertThat(store.findLatest(CUSTOMER).orElseThrow().state()).isEqualTo(RegistrationState.RESERVED);
    }

    @Test
    void completeChangesNothingWhenTheUsernameAlreadyBelongsToSomeone() {
        jdbc.sql("""
                INSERT INTO CUSTOMER_AUTHENTICATION (CUSTOMER_ID, USER_NAME, IDENTITY_ISSUER,
                    IDENTITY_SUBJECT, STATUS, CREATED_AT, UPDATED_AT)
                VALUES ('11111', 'Alice', 'iss', 'other-sub', 'ACTIVE', NOW(6), NOW(6))""").update();
        Registration reserved = reserved(store.reserve(fresh(CUSTOMER, "alice", 1)));
        Registration userCreated = store.save(reserved.markUserCreated("iss", "sub-1")).orElseThrow();
        Registration smsAccepted = store.save(userCreated.markSmsAccepted()).orElseThrow();

        assertThat(store.complete(smsAccepted.complete())).isEqualTo(CompleteResult.IDENTITY_TAKEN);
        assertThat(store.findLatest(CUSTOMER).orElseThrow().state()).isEqualTo(RegistrationState.SMS_ACCEPTED);
        assertThat(identities.count()).isEqualTo(1);
    }

    private Registration fresh(CustomerId customerId, String userName, int digestFill) {
        return Registration.reserve(RegistrationId.random(), customerId, new UserName(userName),
                digest(digestFill), expires);
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
