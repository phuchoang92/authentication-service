package com.vpbank.dcp.infrastructure.adapter.out.redis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.out.replay.ReplayAttempt;
import com.vpbank.dcp.core.port.out.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.core.port.out.replay.ReplayReservation;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordReplayAttempt;
import com.vpbank.dcp.core.port.out.password.PasswordReplayResult;
import com.vpbank.dcp.core.port.out.guard.SubjectBlock;
import com.vpbank.dcp.core.port.out.guard.SubjectBlockResult;
import com.vpbank.dcp.core.port.out.authority.ControlClosure;
import com.vpbank.dcp.core.port.out.authority.ControlCloseResult;
import com.vpbank.dcp.core.port.out.authority.ClosedGeneration;
import com.vpbank.dcp.core.port.out.authority.GenerationInstallResult;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GenerationKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GuardKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.PasswordProofReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingControlCodec;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingControlSnapshot;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingState;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.SubjectGuardCodec;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.TokenLookupHasher;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.testsupport.ContractVectors;
import java.time.Instant;
import java.util.Properties;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tools.jackson.databind.JsonNode;

@Testcontainers
class RedisReplayAuthorityIT {

    private static final String SCRIPT_SHA256 =
            "ad0c9e765269fe2f451b3520e662b3a9d83b3746ecb3157b4cd941f207d7c335";
    private static final String SUBJECT_BLOCK_SHA256 =
            "0874127dccef414f2456cbfb11ff3034d6b4127769d91e807a47dd90f0e7fff1";
    private static final String PASSWORD_REPLAY_SHA256 =
            "1a8ab1738ea33ee578f64a6c0c1d009fa3d6a00cfe79d9bb7624fb157eada77a";
    private static final String CLOSE_CONTROL_SHA256 =
            "38ac6c49c6f9394efb54ab502c5f131c800c4c361cb9484f7f584c3a0b062af4";
    private static final String INSTALL_CLOSED_SHA256 =
            "e784f0e373bfd6e45b828902e9f539ce45b48fba8995164a0d52ed1c9dd4a424";
    private static final AuthorityScope SCOPE = new AuthorityScope("bank-dev-neo");

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(
            "redis@sha256:3b73847e72874be07e6657b129a94761662b79bc0f679273757d4218573b2a98")
            .withExposedPorts(6379);

    private LettuceConnectionFactory factory;
    private StringRedisTemplate redis;
    private GenerationKeys generationKeys;
    private ReplayKeys replayKeys;
    private RedisReplayProtection adapter;
    private UUID generation;

    @BeforeEach
    void connectFreshAuthority() {
        factory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(
                REDIS.getHost(), REDIS.getMappedPort(6379)));
        factory.afterPropertiesSet();
        redis = new StringRedisTemplate(factory);
        redis.afterPropertiesSet();
        redis.getConnectionFactory().getConnection().serverCommands().flushDb();
        generationKeys = new GenerationKeys(SCOPE);
        replayKeys = new ReplayKeys(SCOPE);
        generation = UUID.randomUUID();
        DefaultRedisScript<String> script = VerifiedAuthorityScript.load(
                "redis/replay_reserve.lua", SCRIPT_SHA256);
        adapter = new RedisReplayProtection(redis, replayKeys, generationKeys, script);
    }

    @AfterEach
    void disconnect() {
        factory.destroy();
    }

    @Test
    void onlyOneReplicaCanReserveSameProof() {
        setReady(Instant.now().plusSeconds(60));
        ReplayAttempt attempt = attempt();
        DefaultRedisScript<String> script = VerifiedAuthorityScript.load(
                "redis/replay_reserve.lua", SCRIPT_SHA256);
        var secondReplica = new RedisReplayProtection(redis, replayKeys, generationKeys, script);

        assertThat(adapter.reserve(attempt)).isEqualTo(ReplayReservation.RESERVED);
        assertThat(secondReplica.reserve(attempt)).isEqualTo(ReplayReservation.REPLAYED);
        assertThat(redis.getExpire(replayKeys.forDpop(attempt.requestKey(), attempt.proofIdDigest())))
                .isBetween(1L, 120L);
    }

    @Test
    void passwordProofsAreReservedAtomicallyAcrossReplicas() {
        setReady(Instant.now().plusSeconds(60));
        PasswordReplayAttempt proof = passwordAttempt();
        RedisPasswordProofReplay first = passwordReplayAdapter(redis);
        RedisPasswordProofReplay second = passwordReplayAdapter(redis);
        assertThat(first.reserve(proof)).isEqualTo(new PasswordReplayResult.Reserved(generation));
        assertThat(second.reserve(proof)).isInstanceOf(PasswordReplayResult.Replayed.class);

        var keys = new PasswordProofReplayKeys(SCOPE);
        assertThat(redis.hasKey(replayKeys.forDpop(proof.requestKey(), proof.proofIds().dpop())))
                .isTrue();
        assertThat(redis.hasKey(keys.forRequestKey(proof.requestKey(),
                proof.proofIds().requestKey()))).isTrue();
        assertThat(redis.hasKey(keys.forDeviceKey(proof.deviceKeyThumbprint(),
                proof.proofIds().deviceKey()))).isTrue();
    }

    @Test
    void wrongTypeOrClosedControlWritesNoPasswordReplayMarkers() {
        PasswordReplayAttempt proof = passwordAttempt();
        var keys = new PasswordProofReplayKeys(SCOPE);
        RedisPasswordProofReplay passwordReplay = passwordReplayAdapter(redis);
        assertThat(passwordReplay.reserve(proof))
                .isInstanceOf(PasswordReplayResult.AuthorityClosed.class);
        setReady(Instant.now().plusSeconds(60));
        String deviceMarker = keys.forDeviceKey(proof.deviceKeyThumbprint(),
                proof.proofIds().deviceKey());
        redis.opsForList().leftPush(deviceMarker, "wrong-type");
        assertThat(passwordReplay.reserve(proof))
                .isInstanceOf(PasswordReplayResult.AuthorityClosed.class);
        assertThat(redis.hasKey(replayKeys.forDpop(proof.requestKey(), proof.proofIds().dpop())))
                .isFalse();
        assertThat(redis.hasKey(keys.forRequestKey(proof.requestKey(),
                proof.proofIds().requestKey()))).isFalse();
    }

    @Test
    void wrongTypeAndStaleGenerationDoNotWriteReplayMarker() {
        setReady(Instant.now().plusSeconds(60));
        ReplayAttempt attempt = attempt();
        String key = replayKeys.forDpop(attempt.requestKey(), attempt.proofIdDigest());
        redis.opsForList().leftPush(key, "invalid-type");
        assertThat(adapter.reserve(attempt)).isEqualTo(ReplayReservation.AUTHORITY_CLOSED);
        assertThat(redis.opsForList().size(key)).isEqualTo(1);

        redis.delete(key);
        assertThat(adapter.reserve(new ReplayAttempt(attempt.requestKey(), attempt.proofIdDigest(),
                UUID.randomUUID()))).isEqualTo(ReplayReservation.AUTHORITY_CLOSED);
        assertThat(redis.hasKey(key)).isFalse();
    }

    @Test
    void missingExpiredOrWrongRunIdControlClosesAdmission() {
        ReplayAttempt attempt = attempt();
        assertThat(adapter.reserve(attempt)).isEqualTo(ReplayReservation.AUTHORITY_CLOSED);
        setReady(Instant.now().minusSeconds(1));
        assertThat(adapter.reserve(attempt)).isEqualTo(ReplayReservation.AUTHORITY_CLOSED);
        redis.opsForHash().put(generationKeys.control(), "leaseUntilMs",
                Long.toString(System.currentTimeMillis() + 60_000));
        redis.opsForHash().put(generationKeys.control(), "redisRunId", "previous-primary-run");
        assertThat(adapter.reserve(attempt)).isEqualTo(ReplayReservation.AUTHORITY_CLOSED);
        redis.opsForHash().put(generationKeys.control(), "redisRunId",
                new RedisServerIdentity(redis).currentRunId());
        redis.opsForHash().put(generationKeys.control(), "unknownField", "value");
        assertThat(adapter.reserve(attempt)).isEqualTo(ReplayReservation.AUTHORITY_CLOSED);
    }

    @Test
    void connectionLossIsNeverAnAllow() {
        setReady(Instant.now().plusSeconds(60));
        factory.destroy();
        assertThatThrownBy(() -> adapter.reserve(attempt()))
                .isInstanceOf(ReplayAuthorityUnavailableException.class);
    }

    @Test
    void lostReplyAfterCommitDoesNotReleaseOrAllowTheProof() {
        setReady(Instant.now().plusSeconds(60));
        var uncertainTransport = new StringRedisTemplate(factory) {
            @Override
            public <T> T execute(RedisScript<T> script, java.util.List<String> keys, Object... args) {
                super.execute(script, keys, args);
                throw new IllegalStateException("reply lost after Redis committed");
            }
        };
        uncertainTransport.afterPropertiesSet();
        var uncertainReplica = new RedisReplayProtection(uncertainTransport,
                replayKeys, generationKeys,
                VerifiedAuthorityScript.load("redis/replay_reserve.lua", SCRIPT_SHA256));
        ReplayAttempt proof = attempt();

        assertThatThrownBy(() -> uncertainReplica.reserve(proof))
                .isInstanceOf(ReplayAuthorityUnavailableException.class);
        assertThat(adapter.reserve(proof)).isEqualTo(ReplayReservation.REPLAYED);
    }

    @Test
    void keyFactoriesMatchFrozenAuthorityVectors() throws Exception {
        JsonNode vectors = ContractVectors.load();
        var authority = vectors.path("authorityKeys");
        byte[] hmacSecret = java.util.HexFormat.of().parseHex(authority.path("lookupSecretHex").asText());
        Digest32 digest = new TokenLookupHasher(new LookupKeyVersion("k1"), hmacSecret)
                .digest(authority.path("token").asText());
        assertThat(digest.base64Url()).isEqualTo(authority.path("lookupDigest").asText());
        assertThat(new SessionKeys().forLookup(new LookupKeyVersion("k1"), digest))
                .isEqualTo(authority.path("sessionKey").asText());

        RequestKeyThumbprint key = new RequestKeyThumbprint(Digest32.fromBase64Url(
                vectors.path("keys").path("Kreq").path("jkt").asText()));
        Digest32 proofId = new Sha256Digests().ofProofId("proof-test-vector-00000002");
        assertThat(replayKeys.forDpop(key, proofId))
                .isEqualTo(authority.path("replayKey").asText());
    }

    @Test
    void subjectBlockIsMonotonicAndPreservesIndependentDenies() {
        setReady(Instant.now().plusSeconds(60));
        UUID subjectId = UUID.randomUUID();
        String guardKey = new GuardKeys(SCOPE).forSubject(subjectId);
        var store = subjectBlockStore();
        SubjectBlock first = new SubjectBlock(subjectId, generation, 1, 3, 2);

        assertThat(store.apply(first)).isEqualTo(SubjectBlockResult.APPLIED);
        assertThat(store.apply(first)).isEqualTo(SubjectBlockResult.ALREADY_APPLIED);
        assertThat(redis.opsForHash().get(guardKey, "customerDenied")).isEqualTo("1");
        assertThat(new SubjectGuardCodec().decode(redis.opsForHash().entries(guardKey))
                .causes().customer()).isTrue();
        assertThat(redis.getExpire(guardKey)).isEqualTo(-1L);

        redis.opsForHash().put(guardKey, "administrativeDenied", "1");
        redis.opsForHash().put(guardKey, "resetOperationId", UUID.randomUUID().toString());
        assertThat(store.apply(new SubjectBlock(subjectId, generation, 2, 4, 3)))
                .isEqualTo(SubjectBlockResult.APPLIED);
        assertThat(redis.opsForHash().get(guardKey, "administrativeDenied")).isEqualTo("1");
        assertThat(redis.opsForHash().get(guardKey, "resetOperationId")).isNotEqualTo("");
        assertThat(store.apply(new SubjectBlock(subjectId, generation, 3, 3, 3)))
                .isEqualTo(SubjectBlockResult.STALE);
    }

    @Test
    void guardWrongTypeHasNoPartialWriteAndCloseFencesReplay() {
        setReady(Instant.now().plusSeconds(60));
        UUID subjectId = UUID.randomUUID();
        String guardKey = new GuardKeys(SCOPE).forSubject(subjectId);
        redis.opsForValue().set(guardKey, "wrong-type");
        assertThat(subjectBlockStore().apply(new SubjectBlock(subjectId, generation, 1, 1, 1)))
                .isEqualTo(SubjectBlockResult.AUTHORITY_CLOSED);
        assertThat(redis.opsForValue().get(guardKey)).isEqualTo("wrong-type");

        var control = new RedisAuthorityControl(redis, new RedisServerIdentity(redis), generationKeys,
                VerifiedAuthorityScript.load("redis/close_control.lua", CLOSE_CONTROL_SHA256));
        assertThat(control.close(new ControlClosure(generation, 2)))
                .isEqualTo(ControlCloseResult.AUTHORITY_CLOSED);
        assertThat(control.close(new ControlClosure(generation, 1)))
                .isEqualTo(ControlCloseResult.CLOSED);
        assertThat(control.close(new ControlClosure(generation, 1)))
                .isEqualTo(ControlCloseResult.ALREADY_CLOSED);
        assertThat(adapter.reserve(attempt())).isEqualTo(ReplayReservation.AUTHORITY_CLOSED);
    }

    @Test
    void generationChangeIsFencedAndNeverOpensAdmission() {
        setReady(Instant.now().plusSeconds(60));
        UUID replacement = UUID.randomUUID();
        UUID controller = UUID.randomUUID();
        Instant lease = Instant.now().plusSeconds(120);
        var installer = new RedisGenerationInstaller(redis, new RedisServerIdentity(redis),
                generationKeys, VerifiedAuthorityScript.load(
                "redis/install_closed_generation.lua", INSTALL_CLOSED_SHA256));

        assertThat(installer.installClosed(new ClosedGeneration(replacement, controller, 1, lease)))
                .isEqualTo(GenerationInstallResult.STALE);
        assertThat(installer.installClosed(new ClosedGeneration(replacement, controller, 2, lease)))
                .isEqualTo(GenerationInstallResult.INSTALLED);
        assertThat(redis.opsForHash().get(generationKeys.control(), "state")).isEqualTo("CLOSED");
        assertThat(adapter.reserve(attempt())).isEqualTo(ReplayReservation.AUTHORITY_CLOSED);
        assertThat(installer.installClosed(new ClosedGeneration(replacement, controller, 2, lease)))
                .isEqualTo(GenerationInstallResult.ALREADY_INSTALLED);
    }

    @Test
    void restoredReadyWithOldRunIdIsReplacedOnlyByHigherFenceClosedGeneration() {
        setReady(Instant.now().plusSeconds(60));
        redis.opsForHash().put(generationKeys.control(), "redisRunId", "old-primary-run");
        var installer = new RedisGenerationInstaller(redis, new RedisServerIdentity(redis),
                generationKeys, VerifiedAuthorityScript.load(
                "redis/install_closed_generation.lua", INSTALL_CLOSED_SHA256));
        assertThat(adapter.reserve(attempt())).isEqualTo(ReplayReservation.AUTHORITY_CLOSED);
        assertThat(installer.installClosed(new ClosedGeneration(UUID.randomUUID(),
                UUID.randomUUID(), 2, Instant.now().plusSeconds(60))))
                .isEqualTo(GenerationInstallResult.INSTALLED);
        assertThat(redis.opsForHash().get(generationKeys.control(), "state")).isEqualTo("CLOSED");
    }

    @Test
    void productionAuthorityPreflightRejectsUnboundedOrEvictingRedis() {
        var preflight = new AuthorityRedisPreflight(redis);
        assertThatThrownBy(preflight::verify)
                .isInstanceOf(InvalidAuthorityRedisConfigurationException.class);
        try {
            redis.execute((RedisCallback<Void>) connection -> {
                connection.serverCommands().setConfig("maxmemory", "134217728");
                connection.serverCommands().setConfig("maxmemory-policy", "noeviction");
                return null;
            });
            preflight.verify();
            redis.execute((RedisCallback<Void>) connection -> {
                connection.serverCommands().setConfig("maxmemory-policy", "allkeys-lru");
                return null;
            });
            assertThatThrownBy(preflight::verify)
                    .isInstanceOf(InvalidAuthorityRedisConfigurationException.class);
        } finally {
            redis.execute((RedisCallback<Void>) connection -> {
                connection.serverCommands().setConfig("maxmemory-policy", "noeviction");
                connection.serverCommands().setConfig("maxmemory", "0");
                return null;
            });
        }
    }

    private RedisSubjectBlockStore subjectBlockStore() {
        return new RedisSubjectBlockStore(redis, new RedisServerIdentity(redis),
                new GuardKeys(SCOPE), generationKeys,
                VerifiedAuthorityScript.load("redis/subject_block.lua", SUBJECT_BLOCK_SHA256));
    }

    private RedisPasswordProofReplay passwordReplayAdapter(StringRedisTemplate template) {
        return new RedisPasswordProofReplay(template, generationKeys, replayKeys,
                new PasswordProofReplayKeys(SCOPE), VerifiedAuthorityScript.load(
                "redis/password_proof_reserve.lua", PASSWORD_REPLAY_SHA256));
    }

    private PasswordReplayAttempt passwordAttempt() {
        ReplayAttempt dpop = attempt();
        Digest32 deviceKey = new Sha256Digests().ofProofId("fixture-device-thumbprint");
        return new PasswordReplayAttempt(dpop.requestKey(), deviceKey,
                new PasswordProofIds(dpop.proofIdDigest(),
                        new Sha256Digests().ofProofId("fixture-request-proof"),
                        new Sha256Digests().ofProofId("fixture-device-proof")));
    }

    private ReplayAttempt attempt() {
        byte[] digest = new byte[32];
        digest[0] = 7;
        return new ReplayAttempt(new RequestKeyThumbprint(Digest32.fromBytes(digest)),
                new Sha256Digests().ofProofId("unique-proof-for-this-test"), generation);
    }

    private void setReady(Instant deadline) {
        String runId = redis.execute((RedisCallback<String>) connection -> {
            Properties info = connection.serverCommands().info("server");
            return info.getProperty("run_id");
        });
        redis.opsForHash().putAll(generationKeys.control(), new ServingControlCodec().encode(
                new ServingControlSnapshot(ServingState.READY, generation, runId,
                        UUID.randomUUID(), 1, deadline)));
    }
}
