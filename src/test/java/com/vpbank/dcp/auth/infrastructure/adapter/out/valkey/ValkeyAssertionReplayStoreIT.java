package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** Used BFF assertion IDs on a real Valkey: hashed key, first use wins once, forgotten after the deadline. */
@Testcontainers
class ValkeyAssertionReplayStoreIT {
    @Container
    static final GenericContainer<?> VALKEY = new GenericContainer<>(ValkeyImage.underTest()).withExposedPorts(6379);

    private static LettuceConnectionFactory connections;
    private static StringRedisTemplate redis;
    private final BffAssertionKeys keys = new BffAssertionKeys();
    private final ValkeyAssertionReplayStore store = new ValkeyAssertionReplayStore(redis, keys, Clock.systemUTC());

    @BeforeAll
    static void connect() {
        connections = new LettuceConnectionFactory(new RedisStandaloneConfiguration(VALKEY.getHost(), VALKEY.getMappedPort(6379)));
        connections.afterPropertiesSet();
        redis = new StringRedisTemplate(connections);
    }

    @AfterAll
    static void close() {
        connections.destroy();
    }

    @BeforeEach
    void clean() {
        redis.getConnectionFactory().getConnection().serverCommands().flushAll();
    }

    @Test
    void theFirstUseWinsOnceUnderAHashedKeyThatExpiresWithTheAssertion() {
        Instant rememberUntil = Instant.now().plusSeconds(35);

        assertThat(store.firstUse("jti-1", rememberUntil)).isTrue();
        assertThat(store.firstUse("jti-1", rememberUntil)).isFalse();
        assertThat(store.firstUse("jti-2", rememberUntil)).isTrue();

        String key = keys.forAssertionId("jti-1");
        assertThat(key).startsWith("bff-assertion:used:v1:").doesNotContain("jti-1").hasSize("bff-assertion:used:v1:".length() + 43);
        assertThat(redis.getExpire(key, TimeUnit.SECONDS)).isBetween(30L, 35L);
    }

    @Test
    void anIdAtItsDeadlineIsRememberedBrieflyThenForgotten() throws InterruptedException {
        assertThat(store.firstUse("jti-late", Instant.now().minusSeconds(1))).isTrue();

        Thread.sleep(20);

        assertThat(redis.hasKey(keys.forAssertionId("jti-late"))).isFalse();
    }

    @Test
    void aStoreThatDoesNotAnswerIsUnavailableNeverAFirstUse() {
        LettuceConnectionFactory deadConnections = new LettuceConnectionFactory(new RedisStandaloneConfiguration("127.0.0.1", 1));
        deadConnections.afterPropertiesSet();
        try {
            ValkeyAssertionReplayStore deadStore = new ValkeyAssertionReplayStore(
                    new StringRedisTemplate(deadConnections), keys, Clock.systemUTC());
            assertThatThrownBy(() -> deadStore.firstUse("jti-3", Instant.now().plusSeconds(30)))
                    .isInstanceOf(RepositoryUnavailableException.class);
        } finally {
            deadConnections.destroy();
        }
    }
}
