package com.vpbank.dcp.infrastructure.adapter.out.redis;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.trusteddevice.KeyExchange;
import com.vpbank.dcp.core.port.out.trusteddevice.LoginKeys;
import com.vpbank.dcp.core.port.out.trusteddevice.PreparedRestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionStep;
import com.vpbank.dcp.core.port.out.trusteddevice.StoredRestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustTarget;
import com.vpbank.dcp.core.port.out.trusteddevice.WrappedServerKey;
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
            "valkey/valkey@sha256:418652cfb58ef879d4978c33553735d7147016032d5aefaa14c828e611eb9dfd")
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
        assertThat(listEntry(prepared)).isEqualTo("v1|" + binding.value());
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
        assertThat(listEntry(prepared)).isEqualTo("v1|-");
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

    /** Each step advances once and the session reads back exactly as it was written. */
    @Test
    void stepsAdvanceOnceAndReadBack() {
        PreparedRestrictedSession prepared = prepared(new TrustTarget.NewDevice(),
                Instant.now().plusSeconds(600));
        store.create(prepared);
        UUID sessionId = prepared.sessionId();
        KeyExchange exchange = new KeyExchange(new WrappedServerKey("w1", new byte[] {1, 2, 3}),
                "server-jwk", randomDigest(), "device-jwk", randomDigest());

        assertThat(store.beginKeyExchange(sessionId, exchange)).isTrue();
        assertThat(store.beginKeyExchange(sessionId, exchange)).isFalse();
        assertThat(store.recordVerifyAttempt(sessionId)).isEqualTo(1);
        assertThat(store.recordVerifyAttempt(sessionId)).isEqualTo(2);
        assertThat(store.recordMfaTransaction(sessionId, "mfa-transaction-1")).isTrue();
        assertThat(store.recordMfaTransaction(sessionId, "mfa-transaction-2")).isFalse();

        StoredRestrictedSession stored = store.find(sessionId).orElseThrow();
        assertThat(stored.step()).isEqualTo(RestrictedSessionStep.MFA);
        assertThat(stored.verifyAttempts()).isEqualTo(2);
        assertThat(stored.mfaTransactionId()).isEqualTo("mfa-transaction-1");
        assertThat(stored.keyExchange().serverKey().ciphertext()).containsExactly(1, 2, 3);
        assertThat(stored.keyExchange().challengeDigest()).isEqualTo(exchange.challengeDigest());
        assertThat(stored.keys()).isEqualTo(prepared.session().keys());

        assertThat(store.consume(sessionId)).isTrue();
        assertThat(store.consume(sessionId)).isFalse();
        assertThat(store.find(sessionId)).isEmpty();
    }

    /** A gate run after expiry must not leave a key without TTL that later reads as a session. */
    @Test
    void gatesOnAnEndedSessionLeaveNothingBehind() {
        UUID gone = UUID.randomUUID();
        KeyExchange exchange = new KeyExchange(new WrappedServerKey("w1", new byte[] {1}),
                "server-jwk", randomDigest(), "device-jwk", randomDigest());
        String key = new SessionKeys().forSession(gone);

        assertThat(store.beginKeyExchange(gone, exchange)).isFalse();
        assertThat(store.recordVerifyAttempt(gone)).isEqualTo(-1);
        assertThat(store.recordMfaTransaction(gone, "mfa-transaction-1")).isFalse();
        assertThat(redis.hasKey(key)).isFalse();
    }

    private PreparedRestrictedSession prepared(TrustTarget target, Instant expiresAt) {
        RestrictedSession session = new RestrictedSession(UUID.randomUUID(),
                new SubjectId(UUID.randomUUID()), new CustomerNumber("CUST-1"), 3, "neo-mobile",
                target, "device-id-1234567890",
                new LoginKeys("request-jwk", randomDigest(), "response-jwk"), "ANDROID",
                identity.currentGeneration().orElseThrow());
        return new PreparedRestrictedSession(session, UUID.randomUUID(), randomDigest(), randomDigest(),
                expiresAt, "envelope", "receipt");
    }

    private Object listEntry(PreparedRestrictedSession prepared) {
        return redis.opsForHash().get(new SessionKeys().forSubjectSessions("neo-mobile",
                prepared.session().owner()), prepared.sessionId().toString());
    }

    private String key(PreparedRestrictedSession prepared) {
        return new SessionKeys().forSession(prepared.sessionId());
    }

    private static Digest32 randomDigest() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Digest32.fromBytes(bytes);
    }
}
