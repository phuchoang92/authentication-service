package com.vpbank.dcp.infrastructure.integration.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.application.password.PasswordLoginReservationResult;
import com.vpbank.dcp.core.application.password.ReservePasswordLoginService;
import com.vpbank.dcp.core.application.password.PasswordLoginIdentityResult;
import com.vpbank.dcp.core.application.password.VerifyPasswordLoginIdentityService;
import com.vpbank.dcp.core.application.password.CheckCustomerLoginEligibilityService;
import com.vpbank.dcp.core.application.password.ConfirmPasswordLoginOwnerService;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerificationOutcome;
import com.vpbank.dcp.core.port.out.keycloak.KeycloakVerificationUnavailableException;
import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceKeyRepository;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordOperationRepository;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordProofVerifier;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.LengthPrefixedSigningInputEncoder;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.PasswordCommandHmac;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisPasswordProofReplay;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.PasswordProofReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.RuntimeKeys;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/** Password login operation test: real Redis and MySQL, with only JOSE verification stubbed. */
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
class PasswordLoginOperationIT {

    private static final AuthorityScope SCOPE = new AuthorityScope("bank-test-neo");
    private static final Sha256Digests DIGESTS = new Sha256Digests();

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(
            DockerImageName.parse("mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_password_admission")
            .withUsername("auth_test")
            .withPassword("test-only-password");

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(
            "redis@sha256:3b73847e72874be07e6657b129a94761662b79bc0f679273757d4218573b2a98")
            .withExposedPorts(6379);

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @Autowired
    private PasswordOperationRepository operations;

    @Autowired
    private PasswordDeviceKeyRepository deviceKeys;

    @Autowired
    private JdbcTemplate jdbc;

    private LettuceConnectionFactory factory;
    private StringRedisTemplate redis;

    @BeforeEach
    void initializeAuthority() {
        jdbc.update("DELETE FROM auth_operation WHERE kind = 'PASSWORD_LOGIN'");
        jdbc.update("DELETE FROM auth_login_journey WHERE method = 'PASSWORD'");
        factory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(
                REDIS.getHost(), REDIS.getMappedPort(6379)));
        factory.afterPropertiesSet();
        redis = new StringRedisTemplate(factory);
        redis.afterPropertiesSet();
        redis.getConnectionFactory().getConnection().serverCommands().flushDb();
        new RedisServerIdentity(redis, new RuntimeKeys(SCOPE)).initialize();
    }

    @AfterEach
    void disconnect() {
        factory.destroy();
    }

    @Test
    void twoReplicasShareReplayGateAndRecoverOnlyOriginalCommand() {
        UUID operationId = UUID.randomUUID();
        ReservePasswordLoginService first = service();
        ReservePasswordLoginService second = service();
        var initial = command(operationId, "password-a", "proof-a");
        var created = (PasswordLoginReservationResult.Reserved) first.reserve(initial);
        assertThat(second.reserve(initial)).isInstanceOf(PasswordLoginReservationResult.Rejected.class);
        assertThat(second.reserve(command(operationId, "password-a", "proof-b")))
                .isEqualTo(new PasswordLoginReservationResult.Existing(operationId, created.journeyId()));
        assertThat(second.reserve(command(operationId, "password-b", "proof-c")))
                .isInstanceOf(PasswordLoginReservationResult.Conflict.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_operation", Integer.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_login_journey", Integer.class))
                .isEqualTo(1);
    }

    @Test
    void rejectedPasswordIsDispatchedOnceAcrossTwoServiceInstances() {
        UUID operationId = UUID.randomUUID();
        AtomicInteger providerCalls = new AtomicInteger();
        VerifyPasswordLoginIdentityService first = checkService(credential -> {
                    providerCalls.incrementAndGet();
                    return new PasswordVerificationOutcome.Rejected();
                });
        VerifyPasswordLoginIdentityService second = checkService(credential -> {
                    providerCalls.incrementAndGet();
                    return new PasswordVerificationOutcome.Rejected();
                });

        assertThat(first.verifyIdentity(command(operationId, "wrong-password", "first")))
                .isInstanceOf(PasswordLoginIdentityResult.Rejected.class);
        assertThat(second.verifyIdentity(command(operationId, "wrong-password", "second")))
                .isInstanceOf(PasswordLoginIdentityResult.Rejected.class);
        assertThat(providerCalls.get()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT state FROM auth_operation WHERE id = UUID_TO_BIN(?)",
                String.class, operationId.toString())).isEqualTo("REJECTED");
    }

    @Test
    void reservedOperationCanBeDispatchedByAnotherReplicaAfterCallerStops() {
        UUID operationId = UUID.randomUUID();
        assertThat(service().reserve(command(operationId, "wrong-password", "initial")))
                .isInstanceOf(PasswordLoginReservationResult.Reserved.class);
        AtomicInteger providerCalls = new AtomicInteger();
        VerifyPasswordLoginIdentityService resumed = checkService(credential -> {
            providerCalls.incrementAndGet();
            return new PasswordVerificationOutcome.Rejected();
        });

        assertThat(resumed.verifyIdentity(command(operationId, "wrong-password", "resume")))
                .isInstanceOf(PasswordLoginIdentityResult.Rejected.class);
        assertThat(providerCalls.get()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT state FROM auth_operation WHERE id = UUID_TO_BIN(?)",
                String.class, operationId.toString())).isEqualTo("REJECTED");
    }

    @Test
    void unknownProviderReplyLeavesDurableUncertaintyAndNeverResendsPassword() {
        UUID operationId = UUID.randomUUID();
        AtomicInteger providerCalls = new AtomicInteger();
        VerifyPasswordLoginIdentityService first = checkService(credential -> {
                    providerCalls.incrementAndGet();
                    throw new KeycloakVerificationUnavailableException();
                });
        VerifyPasswordLoginIdentityService second = checkService(credential -> {
                    providerCalls.incrementAndGet();
                    return new PasswordVerificationOutcome.Rejected();
                });

        assertThat(first.verifyIdentity(command(operationId, "password-a", "first")))
                .isInstanceOf(PasswordLoginIdentityResult.Processing.class);
        assertThat(second.verifyIdentity(command(operationId, "password-a", "second")))
                .isInstanceOf(PasswordLoginIdentityResult.Processing.class);
        assertThat(providerCalls.get()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT state FROM auth_operation WHERE id = UUID_TO_BIN(?)",
                String.class, operationId.toString())).isEqualTo("UNCERTAIN");
    }

    private VerifyPasswordLoginIdentityService checkService(DirectGrantPasswordVerifier verifier) {
        CheckCustomerLoginEligibilityService snapshots = new CheckCustomerLoginEligibilityService(
                mock(CustomerDirectory.class), Duration.ofSeconds(30));
        ConfirmPasswordLoginOwnerService customer = new ConfirmPasswordLoginOwnerService(snapshots,
                mock(CustomerOwnerRepository.class), "test-policy");
        return new VerifyPasswordLoginIdentityService(service(), operations, verifier, customer,
                Clock.systemUTC());
    }

    private ReservePasswordLoginService service() {
        PasswordProofVerifier syntheticVerifier = (request, storedKey) -> {
            String proofId = request.wire().requestKeyProof();
            return new VerifiedPasswordProofs(new RequestKeyThumbprint(digest(1)), digest(2),
                    null, new PasswordProofIds(DIGESTS.ofProofId(proofId + "-dpop"),
                    DIGESTS.ofProofId(proofId + "-kreq"), null), "{}", "{}");
        };
        var replay = new RedisPasswordProofReplay(redis,
                new RedisServerIdentity(redis, new RuntimeKeys(SCOPE)),
                new ReplayKeys(SCOPE), new PasswordProofReplayKeys(SCOPE));
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 17);
        var hasher = new PasswordCommandHmac("h1", Map.of("h1", key),
                new LengthPrefixedSigningInputEncoder());
        return new ReservePasswordLoginService(deviceKeys, syntheticVerifier, replay,
                hasher, operations);
    }

    private PasswordLoginCommand command(UUID operationId, String password, String proofId) {
        var operation = new PasswordOperationContext(operationId, "neo-mobile", "ANDROID",
                "install-1", "alice", null);
        var wire = new PasswordWireProofs(
                URI.create("https://api.bank.test/api/v1/authentications/password"),
                proofId + "-dpop", proofId, null, "{}");
        Instant now = Instant.now();
        return new PasswordLoginCommand(operation, new PasswordVerification("alice", password),
                wire, now, now.plusSeconds(120), now.plusSeconds(300));
    }

    private Digest32 digest(int fill) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) fill);
        return Digest32.fromBytes(bytes);
    }
}
