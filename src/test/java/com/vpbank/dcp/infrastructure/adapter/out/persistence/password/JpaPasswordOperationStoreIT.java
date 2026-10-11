package com.vpbank.dcp.infrastructure.adapter.out.persistence.password;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.out.password.PasswordDispatchResult;
import com.vpbank.dcp.core.port.out.password.PasswordCredentialRecordResult;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceKeyStore;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordOperationStore;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordReservation;
import com.vpbank.dcp.core.port.out.password.PasswordReservationFingerprints;
import com.vpbank.dcp.core.port.out.password.PasswordReservationResult;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "server.ssl.enabled=false",
        "auth.authority.scope=bank-test-neo",
        "auth.ingress.external-origin=https://api.bank.test",
        "auth.ingress.allowed-workload-uris=spiffe://bank.test/mobile-bff",
        "spring.datasource.hikari.maximum-pool-size=10",
        "spring.data.redis.host=127.0.0.1",
        "spring.data.redis.port=1",
        "spring.data.redis.ssl.enabled=false"
})
class JpaPasswordOperationStoreIT {

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(
            DockerImageName.parse("mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_password_test")
            .withUsername("auth_test")
            .withPassword("test-only-password");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @Autowired
    private PasswordOperationStore store;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private PasswordDeviceKeyStore deviceKeys;

    @BeforeEach
    void clearPasswordOperations() {
        jdbc.update("DELETE FROM auth_operation WHERE kind = 'PASSWORD_LOGIN'");
        jdbc.update("DELETE FROM auth_login_journey WHERE method = 'PASSWORD'");
    }

    @Test
    void reservesOnceAndClaimsDispatchOnce() {
        PasswordReservation request = reservation(UUID.randomUUID(), digest(4));
        var created = (PasswordReservationResult.Created) store.reserve(request);
        var existing = (PasswordReservationResult.Existing) store.reserve(request);
        assertThat(existing.operationId()).isEqualTo(request.operation().operationId());
        assertThat(existing.journeyId()).isEqualTo(created.journeyId());
        assertThat(existing.commandDigest()).isEqualTo(request.fingerprints().command());
        assertThat(existing.commandKeyId()).isEqualTo("h1");
        String clock = jdbc.queryForObject("""
                SELECT CONCAT(state, '|', deadline, '|', UTC_TIMESTAMP(6))
                  FROM auth_operation WHERE id = UUID_TO_BIN(?)
                """, String.class, request.operation().operationId().toString());
        assertThat(jdbc.queryForObject("""
                SELECT deadline > UTC_TIMESTAMP(6)
                  FROM auth_operation WHERE id = UUID_TO_BIN(?)
                """, Boolean.class, request.operation().operationId().toString()))
                .as(clock).isTrue();
        assertThat(store.claimDispatch(request.operation().operationId()))
                .isEqualTo(PasswordDispatchResult.CLAIMED);
        assertThat(journeyState(created.journeyId())).isEqualTo("CREDENTIAL_PROCESSING");
        assertThat(store.claimDispatch(request.operation().operationId()))
                .isEqualTo(PasswordDispatchResult.ALREADY_CLAIMED);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_operation", Integer.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_login_journey", Integer.class))
                .isEqualTo(1);
    }

    @Test
    void definiteRejectionFailsJourneyAndCannotBeRedispatched() {
        PasswordReservation request = reservation(UUID.randomUUID(), digest(4));
        PasswordReservationResult.Created created =
                (PasswordReservationResult.Created) store.reserve(request);
        assertThat(store.claimDispatch(request.operation().operationId()))
                .isEqualTo(PasswordDispatchResult.CLAIMED);

        assertThat(store.recordRejection(request.operation().operationId()))
                .isEqualTo(PasswordCredentialRecordResult.RECORDED);
        assertThat(store.recordRejection(request.operation().operationId()))
                .isEqualTo(PasswordCredentialRecordResult.ALREADY_RECORDED);
        assertThat(journeyState(created.journeyId())).isEqualTo("FAILED");
        assertThat(operationState(request.operation().operationId())).isEqualTo("REJECTED");
        assertThat(store.claimDispatch(request.operation().operationId()))
                .isEqualTo(PasswordDispatchResult.ALREADY_CLAIMED);
    }

    @Test
    void unknownKeycloakOutcomeIsDurableAndNeverRedispatched() {
        PasswordReservation request = reservation(UUID.randomUUID(), digest(4));
        PasswordReservationResult.Created created =
                (PasswordReservationResult.Created) store.reserve(request);
        assertThat(store.claimDispatch(request.operation().operationId()))
                .isEqualTo(PasswordDispatchResult.CLAIMED);

        assertThat(store.recordUncertain(request.operation().operationId()))
                .isEqualTo(PasswordCredentialRecordResult.RECORDED);
        assertThat(store.recordUncertain(request.operation().operationId()))
                .isEqualTo(PasswordCredentialRecordResult.ALREADY_RECORDED);
        assertThat(operationState(request.operation().operationId())).isEqualTo("UNCERTAIN");
        assertThat(journeyState(created.journeyId())).isEqualTo("CREDENTIAL_PROCESSING");
        assertThat(store.claimDispatch(request.operation().operationId()))
                .isEqualTo(PasswordDispatchResult.ALREADY_CLAIMED);
        assertThat(store.recordRejection(request.operation().operationId()))
                .isEqualTo(PasswordCredentialRecordResult.NOT_RECORDABLE);
    }

    @Test
    void cancelledJourneyCannotClaimPasswordDispatch() {
        PasswordReservation request = reservation(UUID.randomUUID(), digest(4));
        PasswordReservationResult.Created created =
                (PasswordReservationResult.Created) store.reserve(request);
        jdbc.update("UPDATE auth_login_journey SET state = 'CANCELLED' WHERE id = UUID_TO_BIN(?)",
                created.journeyId().toString());

        assertThat(store.claimDispatch(request.operation().operationId()))
                .isEqualTo(PasswordDispatchResult.NOT_CLAIMABLE);
        assertThat(operationState(request.operation().operationId())).isEqualTo("RESERVED");
    }

    @Test
    void twoCallersCanClaimOnlyOnePasswordDispatch() throws Exception {
        PasswordReservation request = reservation(UUID.randomUUID(), digest(4));
        store.reserve(request);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var first = workers.submit(() -> claimTogether(request.operation().operationId(), ready, start));
            var second = workers.submit(() -> claimTogether(request.operation().operationId(), ready, start));
            assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            assertThat(java.util.List.of(first.get(10, TimeUnit.SECONDS),
                    second.get(10, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(PasswordDispatchResult.CLAIMED,
                            PasswordDispatchResult.ALREADY_CLAIMED);
        }
    }

    private PasswordDispatchResult claimTogether(UUID operationId, CountDownLatch ready,
                                                 CountDownLatch start) throws InterruptedException {
        ready.countDown();
        if (!start.await(5, TimeUnit.SECONDS)) {
            throw new IllegalStateException("Test start latch timed out");
        }
        return store.claimDispatch(operationId);
    }

    private String operationState(UUID operationId) {
        return jdbc.queryForObject("SELECT state FROM auth_operation WHERE id = UUID_TO_BIN(?)",
                String.class, operationId.toString());
    }

    private String journeyState(UUID journeyId) {
        return jdbc.queryForObject("SELECT state FROM auth_login_journey WHERE id = UUID_TO_BIN(?)",
                String.class, journeyId.toString());
    }

    @Test
    void competingReservationsHaveOneJourneyAndExposeStoredDigest() throws Exception {
        PasswordReservation firstRequest = reservation(UUID.randomUUID(), digest(4));
        PasswordReservation changedRequest = withCommandDigest(firstRequest, digest(5));
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var first = workers.submit(() -> reserveTogether(firstRequest, ready, start));
            var second = workers.submit(() -> reserveTogether(changedRequest, ready, start));
            assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            assertThat(first.get(10, TimeUnit.SECONDS)).isInstanceOfAny(
                    PasswordReservationResult.Created.class, PasswordReservationResult.Existing.class);
            assertThat(second.get(10, TimeUnit.SECONDS)).isInstanceOfAny(
                    PasswordReservationResult.Created.class, PasswordReservationResult.Existing.class);
        }
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_operation", Integer.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_login_journey", Integer.class))
                .isEqualTo(1);
        var existing = (PasswordReservationResult.Existing) store.reserve(firstRequest);
        assertThat(existing.commandDigest()).isIn(digest(4), digest(5));
    }

    @Test
    void operationIdCollisionRollsBackNewJourney() {
        PasswordReservation valid = reservation(UUID.randomUUID(), digest(4));
        store.reserve(valid);
        var old = valid.fingerprints();
        var collision = new PasswordReservation(valid.operation(), valid.proofs(),
                new PasswordReservationFingerprints(digest(9), digest(10), old.command(),
                        old.commandKeyId(), old.installation()), valid.now(),
                valid.credentialDeadline(), valid.journeyDeadline());
        assertThat(store.reserve(collision)).isInstanceOf(PasswordReservationResult.Conflict.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_operation", Integer.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_login_journey", Integer.class))
                .isEqualTo(1);
        assertThat(store.claimDispatch(valid.operation().operationId()))
                .isEqualTo(PasswordDispatchResult.CLAIMED);
    }

    @Test
    void idempotencyConstraintReturnsOriginalOperationWithoutAnExtraJourney() {
        PasswordReservation original = reservation(UUID.randomUUID(), digest(4));
        store.reserve(original);
        PasswordReservation alternate = reservation(UUID.randomUUID(), digest(4));
        var sameIdempotency = new PasswordReservationFingerprints(
                original.fingerprints().ownerScope(), original.fingerprints().idempotency(),
                alternate.fingerprints().command(), alternate.fingerprints().commandKeyId(),
                alternate.fingerprints().installation());
        PasswordReservation duplicate = new PasswordReservation(alternate.operation(),
                alternate.proofs(), sameIdempotency, alternate.now(),
                alternate.credentialDeadline(), alternate.journeyDeadline());

        PasswordReservationResult result = store.reserve(duplicate);
        assertThat(result).isInstanceOf(PasswordReservationResult.Existing.class);
        assertThat(((PasswordReservationResult.Existing) result).operationId())
                .isEqualTo(original.operation().operationId());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_login_journey",
                Integer.class)).isEqualTo(1);
    }

    @Test
    void deviceKeyLookupRequiresActiveBindingAndMatchingInstallation() {
        UUID subjectId = UUID.randomUUID();
        UUID bindingId = UUID.randomUUID();
        UUID keyId = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO auth_subject
                (id, customer_id, customer_status_version, customer_status_checked_at,
                 status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), ?, 1, UTC_TIMESTAMP(6), 'ELIGIBLE',
                        'test-policy', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subjectId.toString(), "customer-" + subjectId);
        jdbc.update("""
                INSERT INTO auth_subject_app
                (subject_id, app_id, status, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), 'neo-mobile', 'ACTIVE', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subjectId.toString());
        jdbc.update("""
                INSERT INTO auth_device_binding
                (id, subject_id, app_id, installation_hash, platform, label, status,
                 policy_version, possession_assurance, platform_assurance, expires_at,
                 created_at, updated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), 'neo-mobile', UNHEX(SHA2('install-1', 256)),
                        'ANDROID', 'Test device', 'ACTIVE', 'test-policy',
                        'MFA_KEY_POSSESSION', 'NONE', UTC_TIMESTAMP(6) + INTERVAL 1 DAY,
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, bindingId.toString(), subjectId.toString());
        byte[] spki = new byte[] {1, 2, 3, 4};
        jdbc.update("""
                INSERT INTO auth_device_key
                (id, subject_id, app_id, binding_id, purpose, public_key_spki, jkt,
                 algorithm, status, expires_at, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), 'neo-mobile', UUID_TO_BIN(?),
                        'DEVICE_POSSESSION', ?, ?, 'ES256', 'ACTIVE',
                        UTC_TIMESTAMP(6) + INTERVAL 1 DAY, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, keyId.toString(), subjectId.toString(), bindingId.toString(), spki,
                digest(11).bytes());

        var matching = new PasswordOperationContext(UUID.randomUUID(), "neo-mobile", "ANDROID",
                "install-1", "alice", bindingId);
        assertThat(deviceKeys.findActive(matching)).isPresent()
                .get().extracting(key -> key.thumbprint()).isEqualTo(digest(11));
        assertThat(deviceKeys.findActive(new PasswordOperationContext(UUID.randomUUID(),
                "neo-mobile", "ANDROID", "wrong-installation", "alice", bindingId)))
                .isEmpty();
        jdbc.update("UPDATE auth_device_binding SET status = 'REVOKED' WHERE id = UUID_TO_BIN(?)",
                bindingId.toString());
        assertThat(deviceKeys.findActive(matching)).isEmpty();
    }

    private PasswordReservationResult reserveTogether(PasswordReservation reservation,
                                                      CountDownLatch ready,
                                                      CountDownLatch start) throws InterruptedException {
        ready.countDown();
        if (!start.await(5, TimeUnit.SECONDS)) {
            throw new IllegalStateException("Test start latch timed out");
        }
        return store.reserve(reservation);
    }

    private PasswordReservation reservation(UUID operationId, Digest32 commandDigest) {
        var operation = new PasswordOperationContext(operationId, "neo-mobile", "ANDROID",
                "installation-test", "alice", null);
        var proofs = new VerifiedPasswordProofs(new RequestKeyThumbprint(digest(1)),
                digest(2), null, new PasswordProofIds(digest(3), digest(4), null),
                "{\"kty\":\"EC\"}", "{\"kty\":\"EC\"}");
        var fingerprints = new PasswordReservationFingerprints(digest(6), digestId(operationId),
                commandDigest, "h1", digest(8));
        Instant now = Instant.now();
        return new PasswordReservation(operation, proofs, fingerprints, now,
                now.plusSeconds(120), now.plusSeconds(300));
    }

    private PasswordReservation withCommandDigest(PasswordReservation original, Digest32 digest) {
        var old = original.fingerprints();
        return new PasswordReservation(original.operation(), original.proofs(),
                new PasswordReservationFingerprints(old.ownerScope(), old.idempotency(),
                        digest, old.commandKeyId(), old.installation()), original.now(),
                original.credentialDeadline(), original.journeyDeadline());
    }

    private Digest32 digest(int fill) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) fill);
        return Digest32.fromBytes(bytes);
    }

    private Digest32 digestId(UUID operationId) {
        try {
            return Digest32.fromBytes(MessageDigest.getInstance("SHA-256")
                    .digest(operationId.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException(unavailable);
        }
    }
}
