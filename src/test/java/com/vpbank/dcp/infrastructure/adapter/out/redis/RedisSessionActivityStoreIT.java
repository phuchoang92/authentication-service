package com.vpbank.dcp.infrastructure.adapter.out.redis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.customer.SubjectId;
import com.vpbank.dcp.core.device.BindingId;
import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.session.SessionAssurance;
import com.vpbank.dcp.core.session.SessionDeadlines;
import com.vpbank.dcp.core.session.CustomerStatusFreshness;
import com.vpbank.dcp.core.session.PreparedSession;
import com.vpbank.dcp.core.session.SessionActivationContext;
import com.vpbank.dcp.core.session.SessionActivationSnapshot;
import com.vpbank.dcp.core.session.SessionApplyResult;
import com.vpbank.dcp.core.session.SessionCandidate;
import com.vpbank.dcp.core.session.SessionDelivery;
import com.vpbank.dcp.core.session.SessionKeyBindings;
import com.vpbank.dcp.core.session.SessionSecurityVersions;
import com.vpbank.dcp.core.session.LiveSession;
import com.vpbank.dcp.core.session.SessionActivityUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.RuntimeKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
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
class RedisSessionActivityStoreIT {

    private static final AuthorityScope SCOPE = new AuthorityScope("bank-activity-it");

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(
            "valkey/valkey@sha256:418652cfb58ef879d4978c33553735d7147016032d5aefaa14c828e611eb9dfd")
            .withExposedPorts(6379);

    private LettuceConnectionFactory factory;
    private StringRedisTemplate redis;
    private RedisSessionAuthority authority;
    private RedisSessionActivityStore store;
    private final UUID sessionId = UUID.randomUUID();
    private final String key = new SessionKeys().forSession(sessionId);

    @BeforeEach
    void connect() {
        factory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(
                REDIS.getHost(), REDIS.getMappedPort(6379)));
        factory.afterPropertiesSet();
        redis = new StringRedisTemplate(factory);
        redis.afterPropertiesSet();
        redis.getConnectionFactory().getConnection().serverCommands().flushDb();
        RedisServerIdentity identity = new RedisServerIdentity(redis, new RuntimeKeys(SCOPE));
        identity.initialize();
        authority = new RedisSessionAuthority(redis, identity, Duration.ofSeconds(60),
                Clock.systemUTC());
        store = new RedisSessionActivityStore(redis, identity);
    }

    @AfterEach
    void disconnect() {
        factory.destroy();
    }

    @Test
    void readsTheSessionThatLoginPublished() {
        PreparedSession published = publish();

        LiveSession live = store.find(sessionId).orElseThrow();

        assertThat(live.requestKey()).isEqualTo(new RequestKeyThumbprint(digest(1)));
        assertThat(live.generation()).isEqualTo(published.candidate().generation());
        assertThat(live.deadlines()).isEqualTo(published.deadlines());
        assertThat(live.version()).isZero();
        assertThat(store.currentGeneration()).contains(published.candidate().generation());
    }

    @Test
    void slideMovesIdleTtlAndVersionTogether() {
        PreparedSession published = publish();
        Instant newIdle = published.deadlines().idleExpiresAt().plusSeconds(120);

        assertThat(store.slideIdle(sessionId, 0, newIdle)).isTrue();

        assertThat(redis.opsForHash().get(key, "idleExpiresAtMs"))
                .isEqualTo(Long.toString(newIdle.toEpochMilli()));
        assertThat(redis.opsForHash().get(key, "sessionVersion")).isEqualTo("1");
        long ttl = redis.getExpire(key, java.util.concurrent.TimeUnit.MILLISECONDS);
        long expected = Duration.between(Instant.now(), newIdle).toMillis();
        assertThat(ttl).isBetween(expected - 2000, expected + 2000);
        assertThat(store.find(sessionId).orElseThrow().deadlines().idleExpiresAt()).isEqualTo(newIdle);
    }

    @Test
    void staleVersionWritesNothing() {
        PreparedSession published = publish();
        var before = redis.opsForHash().entries(key);

        assertThat(store.slideIdle(sessionId, 7, published.deadlines().idleExpiresAt().plusSeconds(60)))
                .isFalse();
        assertThat(redis.opsForHash().entries(key)).isEqualTo(before);
    }

    @Test
    void deletedSessionIsNeverRecreated() {
        PreparedSession published = publish();
        LiveSession live = store.find(sessionId).orElseThrow();
        assertThat(authority.revoke(published)).isTrue();

        assertThat(store.slideIdle(sessionId, live.version(),
                published.deadlines().idleExpiresAt().plusSeconds(60))).isFalse();
        assertThat(redis.hasKey(key)).isFalse();
        assertThat(store.find(sessionId)).isEmpty();
    }

    @Test
    void concurrentSlidesOnTheSameVersionLetExactlyOneWin() throws Exception {
        PreparedSession published = publish();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            for (int round = 0; round < 10; round++) {
                long version = store.find(sessionId).orElseThrow().version();
                Instant newIdle = published.deadlines().idleExpiresAt().plusSeconds(round + 1);
                CountDownLatch start = new CountDownLatch(1);
                List<Future<Boolean>> results = new ArrayList<>();
                for (int writer = 0; writer < 8; writer++) {
                    results.add(pool.submit(() -> {
                        start.await();
                        return store.slideIdle(sessionId, version, newIdle);
                    }));
                }
                start.countDown();
                int wins = 0;
                for (Future<Boolean> result : results) {
                    wins += result.get() ? 1 : 0;
                }
                assertThat(wins).as("round %d", round).isEqualTo(1);
                assertThat(redis.opsForHash().get(key, "sessionVersion"))
                        .isEqualTo(Long.toString(version + 1));
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void sessionThatIsNotActiveIsNotFound() {
        publish();
        redis.opsForHash().put(key, "state", "LOCKED");

        assertThat(store.find(sessionId)).isEmpty();
    }

    @Test
    void unexpectedFieldSetIsNotFound() {
        publish();
        redis.opsForHash().put(key, "extra", "x");

        assertThat(store.find(sessionId)).isEmpty();
    }

    @Test
    void corruptValueIsNotFound() {
        publish();
        redis.opsForHash().put(key, "idleExpiresAtMs", "soon");

        assertThat(store.find(sessionId)).isEmpty();
    }

    @Test
    void keyWithoutTtlIsNotFound() {
        publish();
        redis.persist(key);

        assertThat(store.find(sessionId)).isEmpty();
    }

    @Test
    void missingKeyIsNotFoundAndNotCreated() {
        assertThat(store.find(sessionId)).isEmpty();
        assertThat(store.slideIdle(sessionId, 0, Instant.now().plusSeconds(60))).isFalse();
        assertThat(redis.hasKey(key)).isFalse();
    }

    @Test
    void unreachableValkeyIsUnavailable() {
        var down = new LettuceConnectionFactory(new RedisStandaloneConfiguration("127.0.0.1", 1));
        down.afterPropertiesSet();
        var template = new StringRedisTemplate(down);
        template.afterPropertiesSet();
        var unreachable = new RedisSessionActivityStore(template,
                new RedisServerIdentity(template, new RuntimeKeys(SCOPE)));
        try {
            assertThatThrownBy(() -> unreachable.find(sessionId))
                    .isInstanceOf(SessionActivityUnavailableException.class);
            assertThatThrownBy(() -> unreachable.slideIdle(sessionId, 0, Instant.now().plusSeconds(60)))
                    .isInstanceOf(SessionActivityUnavailableException.class);
            assertThat(unreachable.currentGeneration()).isEmpty();
        } finally {
            down.destroy();
        }
    }

    /** Publishes through the real login adapter so both adapters agree on the hash format. */
    private PreparedSession publish() {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        SessionActivationSnapshot snapshot = new SessionActivationSnapshot(
                new SessionActivationContext(UUID.randomUUID(), new SubjectId(UUID.randomUUID()),
                        "neo-mobile", new BindingId(UUID.randomUUID())),
                new SessionKeyBindings(digest(1), "{}", "{}", digest(2)),
                new SessionSecurityVersions(0, 0, 0),
                new CustomerStatusFreshness(1, now.plusSeconds(600)),
                new SessionAssurance(SessionAssurance.DevicePossession.MFA_KEY_POSSESSION,
                        SessionAssurance.PlatformEvidence.NONE,
                        SessionAssurance.BiometricEnforcement.NOT_APPLICABLE),
                false);
        PreparedSession session = new PreparedSession(snapshot,
                new SessionCandidate(UUID.randomUUID(), sessionId,
                        authority.currentGeneration().orElseThrow(), digest(3), digest(4)),
                new SessionDelivery("encrypted-only", "signed-receipt",
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", now.plusSeconds(120)),
                SessionDeadlines.createdAt(now));
        assertThat(authority.apply(session)).isEqualTo(SessionApplyResult.APPLIED);
        return session;
    }

    private static Digest32 digest(int marker) {
        byte[] bytes = new byte[32];
        bytes[0] = (byte) marker;
        return Digest32.fromBytes(bytes);
    }
}
