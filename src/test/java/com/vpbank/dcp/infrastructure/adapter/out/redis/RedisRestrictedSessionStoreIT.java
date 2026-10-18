package com.vpbank.dcp.infrastructure.adapter.out.redis;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import com.vpbank.dcp.core.port.out.trusteddevice.LoginKeys;
import com.vpbank.dcp.core.port.out.trusteddevice.PreparedRestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustTarget;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.RuntimeKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class RedisRestrictedSessionStoreIT {
    private static final AuthorityScope SCOPE = new AuthorityScope("bank-restricted-it");

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(
            "redis@sha256:3b73847e72874be07e6657b129a94761662b79bc0f679273757d4218573b2a98")
            .withExposedPorts(6379);

    private LettuceConnectionFactory factory;
    private StringRedisTemplate redis;
    private RedisServerIdentity identity;
    private RedisRestrictedSessionStore store;

    @BeforeEach
    void connect() {
        factory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(
                REDIS.getHost(), REDIS.getMappedPort(6379)));
        factory.afterPropertiesSet();
        redis = new StringRedisTemplate(factory);
        redis.afterPropertiesSet();
        redis.getConnectionFactory().getConnection().serverCommands().flushDb();
        identity = new RedisServerIdentity(redis, new RuntimeKeys(SCOPE));
        identity.initialize();
        store = new RedisRestrictedSessionStore(redis, identity, Clock.systemUTC());
    }

    @AfterEach
    void disconnect() {
        factory.destroy();
    }

    @Test
    void knownDeviceIsStoredInTheSessionKeySpaceWithItsBindingAndExpiry() {
        BindingId binding = new BindingId(UUID.randomUUID());
        Digest32 deviceKey = randomDigest();
        PreparedRestrictedSession prepared = prepared(
                new TrustTarget.KnownDevice(binding, deviceKey, 4), Instant.now().plusSeconds(600));

        assertThat(store.create(prepared)).isTrue();

        Map<Object, Object> stored = redis.opsForHash().entries(key(prepared));
        assertThat(stored).containsEntry("state", "NEED_TRUSTED_DEVICE")
                .containsEntry("step", "OPEN")
                .containsEntry("target", "KNOWN_DEVICE")
                .containsEntry("deviceBindingId", binding.value().toString())
                .containsEntry("deviceKeyJkt", deviceKey.base64Url())
                .containsEntry("deviceSecurityVersion", "4")
                .containsEntry("subjectId", prepared.session().owner().value().toString())
                .containsEntry("customerNumber", "CUST-1")
                .containsEntry("deviceIdDigest", prepared.deviceIdDigest().base64Url())
                .containsEntry("verifyAttempts", "0")
                .containsEntry("platform", "ANDROID")
                .containsEntry("requestPublicJwk", "request-jwk")
                .containsEntry("responsePublicJwk", "response-jwk");
        Long ttl = redis.getExpire(key(prepared), TimeUnit.SECONDS);
        assertThat(ttl).isBetween(590L, 600L);
    }

    /** The plaintext device ID and the token never reach Valkey; only their digests do. */
    @Test
    void newDeviceHasNoBindingFieldsAndNoPlaintextIdentifiers() {
        PreparedRestrictedSession prepared = prepared(new TrustTarget.NewDevice(),
                Instant.now().plusSeconds(600));

        assertThat(store.create(prepared)).isTrue();

        Map<Object, Object> stored = redis.opsForHash().entries(key(prepared));
        assertThat(stored).containsEntry("target", "NEW_DEVICE")
                .doesNotContainKeys("deviceBindingId", "deviceKeyJkt", "deviceSecurityVersion");
        assertThat(stored.values()).doesNotContain(prepared.session().deviceId());
    }

    @Test
    void existingKeyIsNotOverwritten() {
        PreparedRestrictedSession prepared = prepared(new TrustTarget.NewDevice(),
                Instant.now().plusSeconds(600));
        redis.opsForHash().put(key(prepared), "state", "ACTIVE");

        assertThat(store.create(prepared)).isFalse();
        assertThat(redis.opsForHash().get(key(prepared), "state")).isEqualTo("ACTIVE");
    }

    @Test
    void alreadyExpiredSessionIsNotStored() {
        PreparedRestrictedSession prepared = prepared(new TrustTarget.NewDevice(),
                Instant.now().minusSeconds(1));

        assertThat(store.create(prepared)).isFalse();
        assertThat(redis.hasKey(key(prepared))).isFalse();
    }

    private PreparedRestrictedSession prepared(TrustTarget target, Instant expiresAt) {
        RestrictedSession session = new RestrictedSession(UUID.randomUUID(),
                new SubjectId(UUID.randomUUID()), new CustomerNumber("CUST-1"), 3, "neo-mobile",
                target, "device-id-1234567890",
                new LoginKeys("request-jwk", randomDigest(), "response-jwk"), "ANDROID",
                identity.currentGeneration().orElseThrow());
        return new PreparedRestrictedSession(session, UUID.randomUUID(),
                new SessionTokenLookup(new LookupKeyVersion("k1"), randomDigest()), randomDigest(),
                expiresAt, "envelope", "receipt");
    }

    private String key(PreparedRestrictedSession prepared) {
        return new SessionKeys().forLookup(prepared.lookup().version(), prepared.lookup().digest());
    }

    private static Digest32 randomDigest() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Digest32.fromBytes(bytes);
    }
}
