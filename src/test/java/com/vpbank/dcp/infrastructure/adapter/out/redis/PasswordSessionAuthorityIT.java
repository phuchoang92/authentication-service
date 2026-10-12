package com.vpbank.dcp.infrastructure.adapter.out.redis;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.out.session.PasswordSessionFacts;
import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;
import com.vpbank.dcp.core.port.out.session.SessionAdmissionResult;
import com.vpbank.dcp.core.port.out.session.SessionApplyResult;
import com.vpbank.dcp.core.port.out.session.VerifiedSessionProof;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.TokenLookupHasher;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingControlCodec;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingControlSnapshot;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingState;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.CustomerFeedKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GenerationKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GuardKeys;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class PasswordSessionAuthorityIT {
    private static final AuthorityScope SCOPE = new AuthorityScope("bank-session-it");
    private static final String APPLY_SHA =
            "429bd544ac3517e4584ff0c7e42ff8c4dff71ef33a1605e23b8725a935b1fdd2";
    private static final String GATE_SHA =
            "55305f7da8345d32d39b0dcee8e7917cbccfaa64f808dc482bbfb95f19123979";

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(
            "redis@sha256:3b73847e72874be07e6657b129a94761662b79bc0f679273757d4218573b2a98")
            .withExposedPorts(6379);

    private LettuceConnectionFactory factory;
    private StringRedisTemplate redis;
    private RedisPasswordSessionAuthority authority;
    private RedisBankingSessionAdmissionStore admissions;
    private UUID generation;
    private UUID subjectId;
    private UUID bindingId;

    @BeforeEach
    void ready() {
        factory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(
                REDIS.getHost(), REDIS.getMappedPort(6379)));
        factory.afterPropertiesSet();
        redis = new StringRedisTemplate(factory);
        redis.afterPropertiesSet();
        redis.getConnectionFactory().getConnection().serverCommands().flushDb();
        RedisServerIdentity identity = new RedisServerIdentity(redis);
        generation = UUID.randomUUID();
        subjectId = UUID.randomUUID();
        bindingId = UUID.randomUUID();
        String runId = identity.currentRunId();
        Instant now = Instant.now();
        redis.opsForHash().putAll(new GenerationKeys(SCOPE).control(),
                new ServingControlCodec().encode(new ServingControlSnapshot(
                        ServingState.READY, generation, runId, UUID.randomUUID(), 1,
                        now.plusSeconds(120))));
        redis.opsForHash().putAll(new CustomerFeedKeys(SCOPE).forSource("customer"), Map.of(
                "schemaVersion", "1", "source", "customer",
                "transportProfileVersion", "integration-test",
                "appliedCheckpointDigest", "test-checkpoint", "observedAtMs",
                Long.toString(now.toEpochMilli()), "validUntilMs",
                Long.toString(now.plusSeconds(120).toEpochMilli()), "state", "CURRENT"));
        redis.opsForHash().putAll(new GuardKeys(SCOPE).forSubject(subjectId), Map.ofEntries(
                Map.entry("schemaVersion", "1"), Map.entry("owner", subjectId.toString()),
                Map.entry("scope", "SUBJECT"), Map.entry("generation", generation.toString()),
                Map.entry("guardVersion", "0"), Map.entry("minCustomerSecurityVersion", "0"),
                Map.entry("minCredentialSecurityVersion", "0"),
                Map.entry("minDeviceSecurityVersion", "0"), Map.entry("customerDenied", "0"),
                Map.entry("administrativeDenied", "0"), Map.entry("resetOperationId", "")));
        redis.opsForHash().putAll(new GuardKeys(SCOPE).forDevice(bindingId), Map.ofEntries(
                Map.entry("schemaVersion", "1"), Map.entry("owner", subjectId.toString()),
                Map.entry("scope", "DEVICE"), Map.entry("bindingId", bindingId.toString()),
                Map.entry("generation", generation.toString()), Map.entry("guardVersion", "0"),
                Map.entry("minCustomerSecurityVersion", "0"),
                Map.entry("minCredentialSecurityVersion", "0"),
                Map.entry("minDeviceSecurityVersion", "0"), Map.entry("customerDenied", "0"),
                Map.entry("administrativeDenied", "0"), Map.entry("resetOperationId", "")));
        authority = new RedisPasswordSessionAuthority(redis, identity, SCOPE,
                VerifiedAuthorityScript.load("redis/password_session_apply.lua", APPLY_SHA),
                VerifiedAuthorityScript.load("redis/password_session_deliver.lua", GATE_SHA),
                "customer", Duration.ofSeconds(60), Clock.systemUTC());
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        admissions = new RedisBankingSessionAdmissionStore(redis, identity,
                new TokenLookupHasher(new LookupKeyVersion("k1"), secret),
                new LookupKeyVersion("k1"), SCOPE,
                VerifiedAuthorityScript.load("redis/password_session_deliver.lua", GATE_SHA),
                "customer", Duration.ofSeconds(60), Duration.ofSeconds(15), new SecureRandom());
    }

    @AfterEach
    void close() { factory.destroy(); }

    @Test
    void publishesOnceAdmitsWithReplayProtectionAndClosesAfterBlock() {
        PreparedPasswordSession candidate = candidate();
        assertThat(authority.currentGeneration()).contains(generation);
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.APPLIED);
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.ALREADY_APPLIED);
        assertThat(authority.deliverable(candidate)).isTrue();

        // The pre-read is not authority. The atomic script checks the same generation and guards.
        var lookup = new com.vpbank.dcp.core.port.out.session.BankingSessionLookup(
                candidate.lookupVersion(), candidate.lookupDigest(), generation,
                candidate.sessionId(), subjectId, bindingId, "neo-mobile",
                new RequestKeyThumbprint(candidate.facts().requestKey()));
        var nonceDigest = new Sha256Digests().sha256(
                candidate.dpopNonce().getBytes(StandardCharsets.US_ASCII));
        var proof = new VerifiedSessionProof(digest(7), nonceDigest, candidate.dpopNonce());
        assertThat(admissions.admit(lookup, proof, true))
                .isInstanceOf(SessionAdmissionResult.Admitted.class);
        assertThat(admissions.admit(lookup, proof, true))
                .isInstanceOf(SessionAdmissionResult.Denied.class);

        redis.opsForHash().put(new GuardKeys(SCOPE).forSubject(subjectId), "customerDenied", "1");
        assertThat(authority.deliverable(candidate)).isFalse();
        assertThat(admissions.admit(lookup,
                new VerifiedSessionProof(digest(8), nonceDigest, candidate.dpopNonce()), true))
                .isInstanceOf(SessionAdmissionResult.AuthorityClosed.class);
    }

    @Test
    void redisLossCannotRecreateAnOldCandidate() {
        PreparedPasswordSession candidate = candidate();
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.APPLIED);
        redis.getConnectionFactory().getConnection().serverCommands().flushDb();
        assertThat(authority.currentGeneration()).isEmpty();
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.AUTHORITY_CLOSED);
        assertThat(authority.deliverable(candidate)).isFalse();
    }

    private PreparedPasswordSession candidate() {
        Instant now = Instant.now();
        var facts = new PasswordSessionFacts(UUID.randomUUID(), UUID.randomUUID(), subjectId,
                "neo-mobile", bindingId, digest(1), "{}", "{}", digest(2),
                0, 0, 0, 1, now.plusSeconds(120), "NONE", false);
        return new PreparedPasswordSession(facts, UUID.randomUUID(), UUID.randomUUID(),
                generation, new LookupKeyVersion("k1"), digest(3), digest(4),
                "encrypted-only", "signed-receipt", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                SessionDeadlines.createdAt(now), now.plusSeconds(120));
    }

    private Digest32 digest(int marker) {
        byte[] bytes = new byte[32];
        bytes[0] = (byte) marker;
        return Digest32.fromBytes(bytes);
    }
}
