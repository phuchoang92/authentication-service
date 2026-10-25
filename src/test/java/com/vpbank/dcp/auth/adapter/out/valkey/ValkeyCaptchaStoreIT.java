package com.vpbank.dcp.auth.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
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

/** CAPTCHA challenges on a real Valkey: HMAC-ed answer, TTL, customer binding, single use. */
@Testcontainers
class ValkeyCaptchaStoreIT {
    @Container
    static final GenericContainer<?> VALKEY = new GenericContainer<>("valkey/valkey:9.1").withExposedPorts(6379);
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00Z");

    private static LettuceConnectionFactory connections;
    private static StringRedisTemplate redis;
    private final CaptchaKeys keys = new CaptchaKeys(new byte[32]);
    private final ValkeyCaptchaStore store = new ValkeyCaptchaStore(redis, keys, Clock.fixed(NOW, ZoneOffset.UTC));

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
    void storesTheDigestNotTheAnswerWithTheExpiryAsTtlAndConsumesOnce() {
        CaptchaId id = CaptchaId.random();
        store.save(id, ALICE, new CaptchaAnswer("AB3CD"), Instant.now().plusSeconds(300));

        String key = "captcha:v1:" + id.value();
        assertThat(redis.opsForHash().entries(key)).containsEntry("customerId", "90359").doesNotContainValue("AB3CD");
        assertThat(redis.getExpire(key, TimeUnit.SECONDS)).isBetween(290L, 300L);

        assertThat(store.consume(id, ALICE, new CaptchaAnswer("ab3cd"))).isTrue();
        assertThat(redis.hasKey(key)).isFalse();
        assertThat(store.consume(id, ALICE, new CaptchaAnswer("ab3cd"))).isFalse();
    }

    @Test
    void wrongAnswerOtherCustomerNobodyOrExpiredIsFalseAndStillConsumes() {
        CaptchaId wrong = CaptchaId.random();
        store.save(wrong, ALICE, new CaptchaAnswer("AB3CD"), Instant.now().plusSeconds(300));
        assertThat(store.consume(wrong, ALICE, new CaptchaAnswer("AB3CE"))).isFalse();
        assertThat(redis.hasKey("captcha:v1:" + wrong.value())).isFalse();

        CaptchaId other = CaptchaId.random();
        store.save(other, new CustomerId("77777"), new CaptchaAnswer("AB3CD"), Instant.now().plusSeconds(300));
        assertThat(store.consume(other, ALICE, new CaptchaAnswer("AB3CD"))).isFalse();

        CaptchaId nobody = CaptchaId.random();
        store.save(nobody, null, new CaptchaAnswer("AB3CD"), Instant.now().plusSeconds(300));
        assertThat(store.consume(nobody, ALICE, new CaptchaAnswer("AB3CD"))).isFalse();

        CaptchaId expired = CaptchaId.random();
        redis.opsForHash().putAll("captcha:v1:" + expired.value(), java.util.Map.of("customerId", "90359",
                "answerDigest", keys.answerDigest(new CaptchaAnswer("AB3CD")), "expiresAtMs",
                Long.toString(NOW.minusSeconds(1).toEpochMilli())));
        assertThat(store.consume(expired, ALICE, new CaptchaAnswer("AB3CD"))).isFalse();
    }
}
