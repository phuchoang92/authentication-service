package com.vpbank.dcp.infrastructure.adapter.out.persistence.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerFreshnessPolicy;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerAcceptance;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.port.out.password.*;
import com.vpbank.dcp.core.port.out.session.*;
import com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.session.*;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import tools.jackson.databind.json.JsonMapper;

@Testcontainers
@Import(JpaPasswordSessionAdapterIT.SessionConfiguration.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "server.ssl.enabled=false", "auth.authority.scope=bank-test-neo",
        "spring.datasource.hikari.maximum-pool-size=10",
        "auth.ingress.external-origin=https://api.bank.test",
        "auth.ingress.allowed-workload-uris=spiffe://bank.test/mobile-bff",
        "spring.data.redis.host=127.0.0.1", "spring.data.redis.port=1",
        "spring.data.redis.ssl.enabled=false"
})
class JpaPasswordSessionAdapterIT {
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.MICROS);
    private static final CustomerFreshnessPolicy FRESHNESS =
            new CustomerFreshnessPolicy(Duration.ofSeconds(300));

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(DockerImageName.parse(
            "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_password_session")
            .withUsername("auth_test").withPassword("test-only-password");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class SessionConfiguration {
        @Bean
        PasswordSessionPersistenceRepository sessionSql(EntityManager sql) {
            return new PasswordSessionPersistenceRepository(sql);
        }

        @Bean
        PasswordDeliveryEscrowCodec escrowCodec(JsonMapper json) {
            return new PasswordDeliveryEscrowCodec(json);
        }

        @Bean
        PasswordSessionRepository sessions(PasswordSessionPersistenceRepository repository,
                TransactionTemplate transactions, PasswordDeliveryEscrowCodec escrow) {
            return new JpaPasswordSessionAdapter(repository, transactions,
                    Clock.fixed(NOW, ZoneOffset.UTC), FRESHNESS, escrow);
        }
    }

    @Autowired PasswordSessionRepository sessions;
    @Autowired PasswordOperationRepository operations;
    @Autowired CustomerOwnerRepository owners;
    @Autowired PasswordSessionPersistenceRepository repository;
    @Autowired PasswordDeliveryEscrowCodec escrow;
    @Autowired TransactionTemplate transactions;
    @Autowired JdbcTemplate jdbc;

    @Test
    void preparationAndCompletionAreIdempotentAndRecoverTheExactDelivery() throws Exception {
        PreparedPasswordSession candidate = candidate();
        UUID operationId = candidate.facts().operationId();
        assertThat(sessions.prepared(operationId)).isEmpty();
        assertThat(sessions.prepare(candidate)).isEqualTo(new PrepareSessionResult.Prepared(candidate));
        assertThat(repository.prepared(operationId)).as("Stored escrow deadline is %s, current SQL time is %s",
                jdbc.queryForObject("SELECT CAST(delivery_deadline AS CHAR) FROM auth_result_escrow WHERE operation_id = UUID_TO_BIN(?)", String.class, operationId.toString()),
                jdbc.queryForObject("SELECT CAST(UTC_TIMESTAMP(6) AS CHAR)", String.class)).isPresent();
        assertThat(sessions.currentFacts(operationId, candidate.facts().subjectId())).contains(candidate.facts());
        assertThat(sessions.prepared(operationId)).contains(candidate);
        assertThat(sessions.prepare(candidate)).isEqualTo(new PrepareSessionResult.Existing(candidate));
        assertThat(sessions.markApplied(operationId, UUID.randomUUID())).isFalse();
        assertThat(sessions.markApplied(operationId, candidate.intentId())).isTrue();
        assertThat(sessions.markApplied(operationId, candidate.intentId())).isTrue();
        assertThat(operationState(operationId)).isEqualTo("COMPLETED");
        assertThat(journeyState(candidate)).isEqualTo("COMPLETED");
        assertThat(intentState(candidate)).isEqualTo("COMPLETED");
        assertThat(sessions.prepared(operationId)).contains(candidate);
    }

    @Test
    void currentFactsExpireAtTheSameExactBoundaryAsTheDomainPolicy() throws Exception {
        var candidate = candidate();
        var facts = candidate.facts();
        var before = at(facts.customerStatusValidUntil().minusNanos(1));
        var expired = at(facts.customerStatusValidUntil());
        assertThat(before.currentFacts(facts.operationId(), facts.subjectId())).contains(facts);
        assertThat(expired.currentFacts(facts.operationId(), facts.subjectId())).isEmpty();
        assertThat(expired.prepare(candidate)).isInstanceOf(PrepareSessionResult.Rejected.class);
        assertThat(journeyState(candidate)).isEqualTo("CREDENTIAL_PROCESSING");
    }

    @Test
    void preparationRollsBackJourneyAndIntentWhenTheEscrowInsertFails() throws Exception {
        var candidate = candidate();
        UUID operationId = candidate.facts().operationId();
        // A real constraint fails the third write after the journey and intent writes.
        jdbc.execute("ALTER TABLE auth_result_escrow ADD CONSTRAINT fail_test_escrow CHECK (operation_id <> X'"
                + operationId.toString().replace("-", "") + "')");
        try {
            assertThatThrownBy(() -> sessions.prepare(candidate)).isInstanceOf(RuntimeException.class);
        } finally {
            jdbc.execute("ALTER TABLE auth_result_escrow DROP CHECK fail_test_escrow");
        }
        assertThat(journeyState(candidate)).isEqualTo("CREDENTIAL_PROCESSING");
        assertThat(operationState(operationId)).isEqualTo("CONFIRMED");
        assertThat(count("auth_authority_intent", operationId)).isZero();
        assertThat(count("auth_result_escrow", operationId)).isZero();
        assertThat(sessions.prepare(candidate)).isInstanceOf(PrepareSessionResult.Prepared.class);
    }

    @Test
    void completionRollsBackIntentAndJourneyWhenOperationCasCannotSucceed() throws Exception {
        var candidate = candidate();
        UUID operationId = candidate.facts().operationId();
        sessions.prepare(candidate);
        jdbc.update("UPDATE auth_operation SET version = 9007199254740991 WHERE id = UUID_TO_BIN(?)",
                operationId.toString());
        assertThatThrownBy(() -> sessions.markApplied(operationId, candidate.intentId()))
                .isInstanceOf(InvalidPasswordSessionPersistenceException.class);
        assertThat(intentState(candidate)).isEqualTo("READY");
        assertThat(journeyState(candidate)).isEqualTo("FINALIZING");
        assertThat(operationState(operationId)).isEqualTo("CONFIRMED");
    }

    @Test
    void rejectsChangedCurrentVersionsAndCorruptedEscrow() throws Exception {
        var candidate = candidate();
        var facts = candidate.facts();
        jdbc.update("UPDATE auth_customer SET customer_security_version = 1 WHERE id = UUID_TO_BIN(?)",
                facts.subjectId().toString());
        assertThat(sessions.prepare(candidate)).isInstanceOf(PrepareSessionResult.Rejected.class);
        jdbc.update("UPDATE auth_customer SET customer_security_version = 0 WHERE id = UUID_TO_BIN(?)",
                facts.subjectId().toString());
        sessions.prepare(candidate);
        jdbc.update("UPDATE auth_customer SET customer_security_version = 1 WHERE id = UUID_TO_BIN(?)",
                facts.subjectId().toString());
        assertThat(sessions.prepared(facts.operationId())).isEmpty();
        jdbc.update("UPDATE auth_customer SET customer_security_version = 0 WHERE id = UUID_TO_BIN(?)",
                facts.subjectId().toString());
        jdbc.update("UPDATE auth_result_escrow SET protected_result = ? WHERE operation_id = UUID_TO_BIN(?)",
                "tampered".getBytes(StandardCharsets.UTF_8), facts.operationId().toString());
        assertThatThrownBy(() -> sessions.prepared(facts.operationId()))
                .isInstanceOf(InvalidPasswordSessionPersistenceException.class);
    }

    private JpaPasswordSessionAdapter at(Instant now) {
        return new JpaPasswordSessionAdapter(repository, transactions,
                Clock.fixed(now, ZoneOffset.UTC), FRESHNESS, escrow);
    }

    private PreparedPasswordSession candidate() throws Exception {
        UUID subjectId = UUID.randomUUID();
        UUID bindingId = UUID.randomUUID();
        UUID operationId = UUID.randomUUID();
        Digest32 deviceKey = digest(UUID.randomUUID().toString());
        Digest32 requestKey = digest(UUID.randomUUID().toString());
        String customerId = "customer-" + subjectId;
        jdbc.update("""
                INSERT INTO auth_customer
                  (id, customer_id, customer_status_version, customer_status_checked_at,
                   status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), ?, 1, ?, 'ELIGIBLE', 'test-policy', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subjectId.toString(), customerId, java.sql.Timestamp.from(NOW));
        jdbc.update("""
                INSERT INTO auth_subject_app (subject_id, app_id, status, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), 'neo-mobile', 'ACTIVE', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subjectId.toString());
        jdbc.update("""
                INSERT INTO auth_device_binding
                  (id, subject_id, app_id, installation_hash, platform, label, status,
                   policy_version, possession_assurance, platform_assurance, expires_at, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), 'neo-mobile', ?, 'ANDROID', 'Test device',
                        'ACTIVE', 'test-policy', 'MFA_KEY_POSSESSION', 'NONE',
                        UTC_TIMESTAMP(6) + INTERVAL 1 DAY, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, bindingId.toString(), subjectId.toString(), digest("installation").bytes());
        jdbc.update("""
                INSERT INTO auth_device_key
                  (id, subject_id, app_id, binding_id, purpose, public_key_spki, jkt,
                   algorithm, status, expires_at, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), 'neo-mobile', UUID_TO_BIN(?),
                        'DEVICE_POSSESSION', ?, ?, 'ES256', 'ACTIVE', UTC_TIMESTAMP(6) + INTERVAL 1 DAY,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, UUID.randomUUID().toString(), subjectId.toString(), bindingId.toString(),
                new byte[]{1, 2, 3}, deviceKey.bytes());
        jdbc.update("""
                UPDATE auth_subject_app SET last_successful_binding_id = UUID_TO_BIN(?)
                 WHERE subject_id = UUID_TO_BIN(?) AND app_id = 'neo-mobile'
                """, bindingId.toString(), subjectId.toString());
        var operation = new PasswordOperationContext(operationId, "neo-mobile", "ANDROID",
                "installation", "alice", bindingId);
        var proofs = new VerifiedPasswordProofs(new RequestKeyThumbprint(requestKey), digest("response"),
                deviceKey, new PasswordProofIds(digest("proof-request"), digest("proof-response"),
                digest("proof-device")), "{\"kty\":\"EC\"}", "{\"kty\":\"EC\"}");
        var fingerprints = new PasswordReservationFingerprints(digest(subjectId.toString()),
                digest(operationId.toString()), digest("command"), "h1", digest("installation"));
        operations.reserve(new PasswordReservation(operation, proofs, fingerprints, NOW,
                NOW.plusSeconds(120), NOW.plusSeconds(600)));
        assertThat(operations.claimDispatch(operationId)).isEqualTo(PasswordDispatchResult.CLAIMED);
        var identity = new VerifiedProviderIdentity("https://auth.bank.test/realms/mobile", operationId.toString());
        assertThat(operations.recordVerifiedIdentity(operationId, identity))
                .isEqualTo(PasswordCredentialRecordResult.RECORDED);
        assertThat(owners.accept(operationId, "neo-mobile", identity,
                new CustomerAuthenticationState(customerId, CustomerStatus.ELIGIBLE, 1, 0, NOW), "test-policy"))
                .isEqualTo(new CustomerOwnerAcceptance.Accepted(subjectId));
        var facts = sessions.currentFacts(operationId, subjectId).orElseThrow();
        return new PreparedPasswordSession(facts, UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
                new LookupKeyVersion("v1"), digest(UUID.randomUUID().toString()), digest("candidate"),
                "encrypted-token", "signed-receipt", "nonce",
                new SessionDeadlines(NOW.plusSeconds(120), NOW.plusSeconds(600)), NOW.plusSeconds(120));
    }

    private Digest32 digest(String value) throws Exception {
        return Digest32.fromBytes(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    private String operationState(UUID operationId) {
        return jdbc.queryForObject("SELECT state FROM auth_operation WHERE id = UUID_TO_BIN(?)",
                String.class, operationId.toString());
    }

    private String journeyState(PreparedPasswordSession candidate) {
        return jdbc.queryForObject("SELECT state FROM auth_login_journey WHERE id = UUID_TO_BIN(?)",
                String.class, candidate.facts().journeyId().toString());
    }

    private String intentState(PreparedPasswordSession candidate) {
        return jdbc.queryForObject("SELECT state FROM auth_authority_intent WHERE id = UUID_TO_BIN(?)",
                String.class, candidate.intentId().toString());
    }

    private int count(String table, UUID operationId) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM " + table + " WHERE operation_id = UUID_TO_BIN(?)",
                Integer.class, operationId.toString());
    }
}
