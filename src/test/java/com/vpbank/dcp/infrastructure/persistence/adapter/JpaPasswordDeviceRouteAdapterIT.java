package com.vpbank.dcp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.domain.device.DeviceCandidate;
import com.vpbank.dcp.core.domain.device.TrustedDeviceRoute;
import com.vpbank.dcp.core.domain.device.TrustedDeviceRouting;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerAcceptance;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.port.out.password.PasswordCredentialRecordResult;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceRouteEvidence;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceRouteRepository;
import com.vpbank.dcp.core.port.out.password.PasswordDispatchResult;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordOperationRepository;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordReservation;
import com.vpbank.dcp.core.port.out.password.PasswordReservationFingerprints;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * The device-route SQL is the gate between a verified password and an ACTIVE token. These
 * cases pin the evidence it returns and the route the core derives from that evidence, so a
 * change to the query cannot silently widen LAST_TRUSTED or downgrade a bad proof to NEW_DEVICE.
 */
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "server.ssl.enabled=false", "auth.authority.scope=bank-test-neo",
        "spring.datasource.hikari.maximum-pool-size=10",
        "auth.ingress.external-origin=https://api.bank.test",
        "auth.ingress.allowed-workload-uris=spiffe://bank.test/mobile-bff",
        "spring.data.redis.host=127.0.0.1", "spring.data.redis.port=1",
        "spring.data.redis.ssl.enabled=false"
})
class JpaPasswordDeviceRouteAdapterIT {
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.MICROS);
    private static final String APP = "neo-mobile";

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(DockerImageName.parse(
            "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_device_route")
            .withUsername("auth_test").withPassword("test-only-password");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @Autowired PasswordDeviceRouteRepository routes;
    @Autowired PasswordOperationRepository operations;
    @Autowired CustomerOwnerRepository owners;
    @Autowired JdbcTemplate jdbc;

    private final TrustedDeviceRouting routing = new TrustedDeviceRouting();

    @Test
    void lastTrustedWhenClaimedBindingIsLastSuccessfulAndProofMatchesTheActiveKey() throws Exception {
        Seed seed = seed(true, true, true, "ACTIVE", true);
        PasswordDeviceRouteEvidence evidence = routes.currentRoute(seed.operationId(), seed.subjectId(), APP)
                .orElseThrow();
        assertThat(evidence.claimedBindingId()).isEqualTo(seed.bindingId());
        assertThat(evidence.lastSuccessfulBindingId()).isEqualTo(seed.bindingId());
        assertThat(evidence.installationHash()).isEqualTo(base64(seed.installation()));
        DeviceCandidate candidate = evidence.candidate().orElseThrow();
        assertThat(candidate.bindingId()).isEqualTo(seed.bindingId());
        assertThat(candidate.ownerId()).isEqualTo(seed.subjectId());
        assertThat(candidate.appId()).isEqualTo(APP);
        assertThat(candidate.installationHash()).isEqualTo(base64(seed.installation()));
        assertThat(candidate.active()).isTrue();
        assertThat(candidate.keyActive()).isTrue();
        assertThat(candidate.possessionVerified()).isTrue();
        assertThat(route(evidence, seed)).isEqualTo(TrustedDeviceRoute.LAST_TRUSTED);
    }

    @Test
    void otherTrustedWhenValidBindingIsNotTheLastSuccessfulOne() throws Exception {
        Seed seed = seed(true, true, false, "ACTIVE", true);
        PasswordDeviceRouteEvidence evidence = routes.currentRoute(seed.operationId(), seed.subjectId(), APP)
                .orElseThrow();
        assertThat(evidence.lastSuccessfulBindingId()).isNull();
        assertThat(evidence.candidate()).isPresent();
        assertThat(evidence.candidate().orElseThrow().possessionVerified()).isTrue();
        assertThat(route(evidence, seed)).isEqualTo(TrustedDeviceRoute.OTHER_TRUSTED);
    }

    @Test
    void newDeviceWhenNoBindingIsClaimed() throws Exception {
        Seed seed = seed(false, false, false, "ACTIVE", true);
        PasswordDeviceRouteEvidence evidence = routes.currentRoute(seed.operationId(), seed.subjectId(), APP)
                .orElseThrow();
        assertThat(evidence.claimedBindingId()).isNull();
        assertThat(evidence.candidate()).isEmpty();
        assertThat(evidence.installationHash()).isEqualTo(base64(seed.installation()));
        assertThat(route(evidence, seed)).isEqualTo(TrustedDeviceRoute.NEW_DEVICE);
    }

    /** A supplied proof that does not match the stored Kdev rejects; it never becomes NEW_DEVICE. */
    @Test
    void rejectedWhenSuppliedDeviceProofDoesNotMatchTheStoredKey() throws Exception {
        Seed seed = seed(true, false, true, "ACTIVE", true);
        PasswordDeviceRouteEvidence evidence = routes.currentRoute(seed.operationId(), seed.subjectId(), APP)
                .orElseThrow();
        DeviceCandidate candidate = evidence.candidate().orElseThrow();
        assertThat(candidate.active()).isTrue();
        assertThat(candidate.possessionVerified()).isFalse();
        assertThat(route(evidence, seed)).isEqualTo(TrustedDeviceRoute.REJECTED);
    }

    @Test
    void rejectedWhenTheStoredKeyIsRevoked() throws Exception {
        Seed seed = seed(true, true, true, "REVOKED", true);
        PasswordDeviceRouteEvidence evidence = routes.currentRoute(seed.operationId(), seed.subjectId(), APP)
                .orElseThrow();
        DeviceCandidate candidate = evidence.candidate().orElseThrow();
        assertThat(candidate.active()).isTrue();
        assertThat(candidate.keyActive()).isFalse();
        assertThat(candidate.possessionVerified()).isFalse();
        assertThat(route(evidence, seed)).isEqualTo(TrustedDeviceRoute.REJECTED);
    }

    /** Route evidence exists only after the owner has been confirmed, never from a mere VERIFIED state. */
    @Test
    void noEvidenceBeforeTheOwnerIsConfirmed() throws Exception {
        Seed seed = seed(true, true, true, "ACTIVE", false);
        assertThat(routes.currentRoute(seed.operationId(), seed.subjectId(), APP)).isEmpty();
    }

    @Test
    void noEvidenceForAnotherSubjectOrApp() throws Exception {
        Seed seed = seed(true, true, true, "ACTIVE", true);
        assertThat(routes.currentRoute(seed.operationId(), UUID.randomUUID(), APP)).isEmpty();
        assertThat(routes.currentRoute(seed.operationId(), seed.subjectId(), "other-app")).isEmpty();
    }

    private TrustedDeviceRoute route(PasswordDeviceRouteEvidence evidence, Seed seed) {
        return routing.decide(seed.subjectId(), APP, evidence.installationHash(),
                evidence.lastSuccessfulBindingId(), evidence.candidate().orElse(null), NOW);
    }

    private record Seed(UUID subjectId, UUID bindingId, UUID operationId, Digest32 installation) { }

    /**
     * Drives the real reservation → dispatch → verified identity → owner confirmation path so the
     * operation reaches CONFIRMED the way production does, rather than by hand-written UPDATEs.
     */
    private Seed seed(boolean claimBinding, boolean proofMatchesKey, boolean lastSuccessful,
                      String keyStatus, boolean confirmOwner) throws Exception {
        UUID subjectId = UUID.randomUUID();
        UUID bindingId = UUID.randomUUID();
        UUID operationId = UUID.randomUUID();
        String installationId = "installation-" + subjectId;
        Digest32 installation = digest(installationId);
        Digest32 keyJkt = digest("kdev-" + subjectId);
        String customerId = "customer-" + subjectId;
        jdbc.update("""
                INSERT INTO auth_customer
                  (id, customer_id, customer_status_version, customer_status_checked_at,
                   status, policy_version, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), ?, 1, ?, 'ELIGIBLE', 'test-policy', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subjectId.toString(), customerId, utc(NOW));
        jdbc.update("""
                INSERT INTO auth_subject_app (subject_id, app_id, status, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), ?, 'ACTIVE', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, subjectId.toString(), APP);
        if (claimBinding) {
            jdbc.update("""
                    INSERT INTO auth_device_binding
                      (id, subject_id, app_id, installation_hash, platform, label, status,
                       policy_version, possession_assurance, platform_assurance, expires_at, created_at, updated_at)
                    VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), ?, ?, 'ANDROID', 'Test device',
                            'ACTIVE', 'test-policy', 'MFA_KEY_POSSESSION', 'NONE',
                            UTC_TIMESTAMP(6) + INTERVAL 1 DAY, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                    """, bindingId.toString(), subjectId.toString(), APP, installation.bytes());
            jdbc.update("""
                    INSERT INTO auth_device_key
                      (id, subject_id, app_id, binding_id, purpose, public_key_spki, jkt,
                       algorithm, status, expires_at, created_at, updated_at)
                    VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), ?, UUID_TO_BIN(?),
                            'DEVICE_POSSESSION', ?, ?, 'ES256', ?, UTC_TIMESTAMP(6) + INTERVAL 1 DAY,
                            UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                    """, UUID.randomUUID().toString(), subjectId.toString(), APP, bindingId.toString(),
                    new byte[]{1, 2, 3}, keyJkt.bytes(), keyStatus);
            if (lastSuccessful) {
                jdbc.update("""
                        UPDATE auth_subject_app SET last_successful_binding_id = UUID_TO_BIN(?)
                         WHERE subject_id = UUID_TO_BIN(?) AND app_id = ?
                        """, bindingId.toString(), subjectId.toString(), APP);
            }
        }
        Digest32 proofJkt = !claimBinding ? null
                : proofMatchesKey ? keyJkt : digest("wrong-proof-" + subjectId);
        var operation = new PasswordOperationContext(operationId, APP, "ANDROID", installationId, "alice",
                claimBinding ? bindingId : null);
        var proofs = new VerifiedPasswordProofs(new RequestKeyThumbprint(digest("kreq-" + subjectId)),
                digest("kenc-" + subjectId), proofJkt,
                new PasswordProofIds(digest("dpop-" + subjectId), digest("req-proof-" + subjectId),
                        proofJkt == null ? null : digest("dev-proof-" + subjectId)),
                "{\"kty\":\"EC\"}", "{\"kty\":\"EC\"}");
        var fingerprints = new PasswordReservationFingerprints(digest("owner-" + subjectId),
                digest(operationId.toString()), digest("command"), "h1", installation);
        operations.reserve(new PasswordReservation(operation, proofs, fingerprints, NOW,
                NOW.plusSeconds(120), NOW.plusSeconds(600)));
        assertThat(operations.claimDispatch(operationId)).isEqualTo(PasswordDispatchResult.CLAIMED);
        var identity = new VerifiedProviderIdentity("https://auth.bank.test/realms/mobile", "sub-" + subjectId);
        assertThat(operations.recordVerifiedIdentity(operationId, identity))
                .isEqualTo(PasswordCredentialRecordResult.RECORDED);
        if (confirmOwner) {
            assertThat(owners.accept(operationId, APP, identity,
                    new CustomerAuthenticationState(customerId, CustomerStatus.ELIGIBLE, 1, 0, NOW), "test-policy"))
                    .isEqualTo(new CustomerOwnerAcceptance.Accepted(subjectId));
        }
        return new Seed(subjectId, bindingId, operationId, installation);
    }

    private static Digest32 digest(String value) throws Exception {
        return Digest32.fromBytes(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    private static String base64(Digest32 digest) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.bytes());
    }

    private static String utc(Instant instant) {
        return DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSSSSS").withZone(ZoneOffset.UTC).format(instant);
    }
}
