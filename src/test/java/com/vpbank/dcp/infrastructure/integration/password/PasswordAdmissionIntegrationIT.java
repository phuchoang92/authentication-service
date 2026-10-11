package com.vpbank.dcp.infrastructure.integration.password;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.application.password.PasswordAdmissionCommand;
import com.vpbank.dcp.core.application.password.PasswordAdmissionResult;
import com.vpbank.dcp.core.application.password.PasswordAdmissionService;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceKeyStore;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordOperationStore;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordProofVerifier;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.ChallengeSigningInput;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.PasswordCommandHmac;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.ProofDigests;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisPasswordProofReplay;
import com.vpbank.dcp.infrastructure.adapter.out.redis.VerifiedAuthorityScript;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GenerationKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.PasswordProofReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingControlCodec;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingControlSnapshot;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingState;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/** Component-level admission test: real Redis and MySQL, with only JOSE verification stubbed. */
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
class PasswordAdmissionIntegrationIT {

    private static final AuthorityScope SCOPE = new AuthorityScope("bank-test-neo");
    private static final String REPLAY_SHA =
            "1a8ab1738ea33ee578f64a6c0c1d009fa3d6a00cfe79d9bb7624fb157eada77a";
    private static final ProofDigests DIGESTS = new ProofDigests();

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
    private PasswordOperationStore operations;

    @Autowired
    private PasswordDeviceKeyStore deviceKeys;

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
        var keys = new GenerationKeys(SCOPE);
        String runId = redis.execute((RedisCallback<String>) connection -> {
            Properties info = connection.serverCommands().info("server");
            return info.getProperty("run_id");
        });
        redis.opsForHash().putAll(keys.control(), new ServingControlCodec().encode(
                new ServingControlSnapshot(ServingState.READY, UUID.randomUUID(), runId,
                        UUID.randomUUID(), 1, Instant.now().plusSeconds(60))));
    }

    @AfterEach
    void disconnect() {
        factory.destroy();
    }

    @Test
    void twoReplicasShareReplayGateAndRecoverOnlyOriginalCommand() {
        UUID operationId = UUID.randomUUID();
        PasswordAdmissionService first = service();
        PasswordAdmissionService second = service();
        var initial = command(operationId, "password-a", "proof-a");
        var created = (PasswordAdmissionResult.Reserved) first.reserve(initial);
        assertThat(second.reserve(initial)).isInstanceOf(PasswordAdmissionResult.Rejected.class);
        assertThat(second.reserve(command(operationId, "password-a", "proof-b")))
                .isEqualTo(new PasswordAdmissionResult.Existing(operationId, created.journeyId()));
        assertThat(second.reserve(command(operationId, "password-b", "proof-c")))
                .isInstanceOf(PasswordAdmissionResult.Conflict.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_operation", Integer.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_login_journey", Integer.class))
                .isEqualTo(1);
    }

    private PasswordAdmissionService service() {
        PasswordProofVerifier syntheticVerifier = (request, storedKey) -> {
            String proofId = request.wire().requestKeyProof();
            return new VerifiedPasswordProofs(new RequestKeyThumbprint(digest(1)), digest(2),
                    null, new PasswordProofIds(DIGESTS.ofProofId(proofId + "-dpop"),
                    DIGESTS.ofProofId(proofId + "-kreq"), null), "{}", "{}");
        };
        var replay = new RedisPasswordProofReplay(redis, new GenerationKeys(SCOPE),
                new ReplayKeys(SCOPE), new PasswordProofReplayKeys(SCOPE),
                VerifiedAuthorityScript.load("redis/password_proof_reserve.lua", REPLAY_SHA));
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 17);
        var hasher = new PasswordCommandHmac("h1", Map.of("h1", key),
                new ChallengeSigningInput());
        return new PasswordAdmissionService(deviceKeys, syntheticVerifier, replay,
                hasher, operations);
    }

    private PasswordAdmissionCommand command(UUID operationId, String password, String proofId) {
        var operation = new PasswordOperationContext(operationId, "neo-mobile", "ANDROID",
                "install-1", "alice", null);
        var wire = new PasswordWireProofs(
                URI.create("https://api.bank.test/api/v1/authentications/password"),
                proofId + "-dpop", proofId, null, "{}");
        Instant now = Instant.now();
        return new PasswordAdmissionCommand(operation, new PasswordVerification("alice", password),
                wire, now, now.plusSeconds(120), now.plusSeconds(300));
    }

    private Digest32 digest(int fill) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) fill);
        return Digest32.fromBytes(bytes);
    }
}
