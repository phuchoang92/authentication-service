package com.vpbank.dcp.infrastructure.adapter.out.redis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.port.out.pending.PendingTotpLogin;
import com.vpbank.dcp.core.port.out.pending.PendingTotpUnavailableException;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.PendingTotpKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.RuntimeKeys;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tools.jackson.databind.json.JsonMapper;

@Testcontainers
class RedisPendingTotpStoreIT {
    private static final AuthorityScope SCOPE = new AuthorityScope("pending-totp-it");

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(
            "redis@sha256:3b73847e72874be07e6657b129a94761662b79bc0f679273757d4218573b2a98")
            .withExposedPorts(6379);

    private LettuceConnectionFactory factory;
    private StringRedisTemplate redis;
    private RedisServerIdentity identity;
    private RedisPendingTotpStore store;

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
        store = new RedisPendingTotpStore(redis, identity, new JsonMapper(), Clock.systemUTC());
    }

    @AfterEach
    void disconnect() {
        factory.destroy();
    }

    @Test
    void pendingChallengeIsSingleUseAndNeverHasNoExpiry() {
        SessionTokenLookup token = token();
        PendingTotpLogin pending = pending(identity.currentGeneration().orElseThrow());

        assertThat(store.create(token, pending)).isTrue();
        assertThat(store.create(token, pending)).isFalse();
        assertThat(store.find(token)).contains(pending);
        assertThat(redis.getExpire(new PendingTotpKeys().forToken(token))).isPositive();
        assertThat(store.consume(token)).contains(pending);
        assertThat(store.consume(token)).isEmpty();
        assertThat(store.find(token)).isEmpty();
    }

    @Test
    void redisLossAndMalformedStateCannotCompleteLogin() {
        SessionTokenLookup token = token();
        assertThat(store.create(token, pending(identity.currentGeneration().orElseThrow()))).isTrue();
        redis.getConnectionFactory().getConnection().serverCommands().flushDb();
        assertThat(store.find(token)).isEmpty();
        assertThat(store.consume(token)).isEmpty();

        redis.opsForValue().set(new PendingTotpKeys().forToken(token), "not-a-valid-record",
                java.time.Duration.ofSeconds(30));
        assertThatThrownBy(() -> store.find(token)).isInstanceOf(PendingTotpUnavailableException.class);
    }

    private SessionTokenLookup token() {
        byte[] digest = new byte[32];
        new java.security.SecureRandom().nextBytes(digest);
        return new SessionTokenLookup(new LookupKeyVersion("test"),
                Digest32.fromBytes(digest));
    }

    private PendingTotpLogin pending(UUID generation) {
        String opaqueId = "QkJCQkJCQkJCQkJCQkJCQg";
        return new PendingTotpLogin(
                new PendingTotpLogin.Identity(UUID.randomUUID(), UUID.randomUUID(), "customer-a",
                        UUID.randomUUID(), "neo-mobile", "installation-1234567890"),
                new PendingTotpLogin.Keys("request-jkt", "request-jwk", "response-jwk", "device-jkt"),
                new PendingTotpLogin.Challenge(opaqueId, opaqueId, Instant.now().plusSeconds(120)),
                new PendingTotpLogin.Versions(1, 2, generation));
    }
}
