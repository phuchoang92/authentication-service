package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.DataType;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** CAPTCHA challenges on a real Valkey: HMAC-ed answer, TTL, customer binding, single use. */
@Testcontainers
class CaptchaChallengeStoreIT {
    @Container
    static final GenericContainer<?> VALKEY = new GenericContainer<>(ValkeyImage.underTest()).withExposedPorts(6379);
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00Z");

    private static LettuceConnectionFactory connections;
    private static StringRedisTemplate redis;
    private final CaptchaAnswerDigest digests = new CaptchaAnswerDigest(new byte[32]);
    private final CaptchaChallengeStore store = storeAt(Clock.fixed(NOW, ZoneOffset.UTC));

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
    void storesTheDigestNotTheAnswerUnderTheCustomerWithTheExpiryAsTtlAndConsumesOnce() {
        store.issue(ALICE, new CaptchaAnswer("AB3CD"), Instant.now().plusSeconds(300));

        String key = "tx:v4:captcha:90359";
        assertThat(redis.type(key)).isEqualTo(DataType.STRING);
        assertThat(redis.opsForValue().get(key))
                .contains(digests.of(new CaptchaAnswer("AB3CD"))).doesNotContain("AB3CD");
        assertThat(redis.getExpire(key, TimeUnit.SECONDS)).isBetween(290L, 300L);

        assertThat(store.consume(ALICE, new CaptchaAnswer("ab3cd"))).isTrue();
        assertThat(redis.hasKey(key)).isFalse();
        assertThat(store.consume(ALICE, new CaptchaAnswer("ab3cd"))).isFalse();
    }

    @Test
    void aNewChallengeReplacesTheCustomersEarlierOne() {
        store.issue(ALICE, new CaptchaAnswer("AB3CD"), Instant.now().plusSeconds(300));
        store.issue(ALICE, new CaptchaAnswer("XY7ZW"), Instant.now().plusSeconds(300));

        assertThat(store.consume(ALICE, new CaptchaAnswer("AB3CD"))).isFalse(); // the earlier answer is gone
        assertThat(redis.hasKey("tx:v4:captcha:90359")).isFalse(); // and the attempt consumed the new one
    }

    @Test
    void wrongAnswerOtherCustomerOrExpiredIsFalseAndStillConsumes() {
        store.issue(ALICE, new CaptchaAnswer("AB3CD"), Instant.now().plusSeconds(300));
        assertThat(store.consume(ALICE, new CaptchaAnswer("AB3CE"))).isFalse();
        assertThat(redis.hasKey("tx:v4:captcha:90359")).isFalse();

        CustomerId bob = new CustomerId("77777");
        store.issue(bob, new CaptchaAnswer("AB3CD"), Instant.now().plusSeconds(300));
        assertThat(store.consume(ALICE, new CaptchaAnswer("AB3CD"))).isFalse(); // Alice has no challenge
        assertThat(store.consume(bob, new CaptchaAnswer("AB3CD"))).isTrue();

        // Still in the store (the server forgets it a little later), but past its deadline on the clock that decides.
        store.issue(ALICE, new CaptchaAnswer("AB3CD"), Instant.now().plusSeconds(2));
        CaptchaChallengeStore later = storeAt(Clock.fixed(Instant.now().plusSeconds(60), ZoneOffset.UTC));
        assertThat(later.consume(ALICE, new CaptchaAnswer("AB3CD"))).isFalse();
        assertThat(redis.hasKey("tx:v4:captcha:90359")).isFalse(); // consumed all the same
    }

    @Test
    void ofManyCallersConsumingTheSameChallengeOnlyOneSucceeds() throws Exception {
        store.issue(ALICE, new CaptchaAnswer("AB3CD"), Instant.now().plusSeconds(300));
        int callers = 16;
        ExecutorService pool = Executors.newFixedThreadPool(callers);
        try {
            List<Callable<Boolean>> attempts = new ArrayList<>();
            for (int caller = 0; caller < callers; caller++) {
                attempts.add(() -> store.consume(ALICE, new CaptchaAnswer("AB3CD")));
            }
            long winners = 0;
            for (Future<Boolean> consumed : pool.invokeAll(attempts)) {
                if (consumed.get(10, TimeUnit.SECONDS)) {
                    winners++;
                }
            }
            assertThat(winners).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void aStoreThatDoesNotAnswerIsUnavailable() {
        LettuceConnectionFactory deadConnections =
                new LettuceConnectionFactory(new RedisStandaloneConfiguration("127.0.0.1", 1));
        deadConnections.afterPropertiesSet();
        try {
            ValkeyTransactionAdapter deadTransactions = transactionsOn(new StringRedisTemplate(deadConnections));
            CaptchaChallengeStore deadStore = new CaptchaChallengeStore(deadTransactions, digests, Clock.fixed(NOW, ZoneOffset.UTC));
            assertThatThrownBy(() -> deadStore.issue(ALICE, new CaptchaAnswer("AB3CD"), Instant.now().plusSeconds(300)))
                    .isInstanceOf(RepositoryUnavailableException.class);
            assertThatThrownBy(() -> deadStore.consume(ALICE, new CaptchaAnswer("AB3CD")))
                    .isInstanceOf(RepositoryUnavailableException.class);
        } finally {
            deadConnections.destroy();
        }
    }

    private CaptchaChallengeStore storeAt(Clock clock) {
        return new CaptchaChallengeStore(transactionsOn(redis), digests, clock);
    }

    private static ValkeyTransactionAdapter transactionsOn(StringRedisTemplate template) {
        return new ValkeyTransactionAdapter(new ValkeyRecordCommands(template), new TransactionKeys(),
                new TransactionJsonCodec(TransactionJsonCodec.strictPayloadJson()));
    }
}
