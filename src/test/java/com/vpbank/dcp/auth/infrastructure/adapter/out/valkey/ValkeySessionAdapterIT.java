package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DomainFixtures;
import com.vpbank.dcp.auth.domain.model.NewSession;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import java.time.Duration;
import java.time.Instant;
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
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/** The adapter against a real Valkey: key layout, TTL, strict decode, and the WATCH/MULTI/EXEC compare-and-set. */
@Testcontainers
class ValkeySessionAdapterIT {
    @Container
    static final GenericContainer<?> VALKEY = new GenericContainer<>("valkey/valkey:9.1").withExposedPorts(6379);
    private static final OpaqueToken TOKEN = new OpaqueToken("s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000001:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    private static final SessionPolicy POLICY = new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20),
            Duration.ofSeconds(30));

    private static LettuceConnectionFactory connections;
    private static StringRedisTemplate redis;
    private final SessionKeys keys = new SessionKeys();
    private final ValkeySessionAdapter store = storeOn(redis);
    /** Stored as milliseconds, so the fixture must not carry finer precision. */
    private final Instant now = Instant.now().minusSeconds(5).truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
    private final NewSession sessionStart = DomainFixtures.mobileSession(
            TOKEN.sessionId(),
            new CustomerId("90359"),
            new DeviceId("dev-1"),
            now);
    private final Session session = Session.start(sessionStart, POLICY);

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
    void createsOneJsonStringUnderTheLookupWithTheIdleDeadlineAsTtl() {
        store.create(session, TOKEN);

        SessionLookup lookup = keys.lookupOf(TOKEN);
        String key = "session:v3:MOBILE:" + lookup.sessionId().value();
        assertThat(redis.type(key)).isEqualTo(DataType.STRING);
        String stored = redis.opsForValue().get(key);
        assertThat(stored).startsWith("{\"schemaVersion\":2,\"sessionId\":\"" + lookup.sessionId().value() + "\"")
                .contains("\"customerId\":\"90359\"").contains("\"sessionVersion\":0")
                .contains("\"secretDigest\":\"" + SessionSecretDigest.of(TOKEN.secret()) + "\"")
                .doesNotContain(TOKEN.secret()); // the secret itself is never stored
        assertThat(redis.getExpire(key, TimeUnit.SECONDS)).isBetween(14 * 60L, 15 * 60L);

        assertThat(store.findByToken(TOKEN)).map(StoredSession::session).contains(session);
        assertThat(store.findByLookup(lookup)).map(StoredSession::session).contains(session);
        assertThat(store.findByLookup(lookup)).map(StoredSession::secretDigest)
                .contains(SessionSecretDigest.of(TOKEN.secret()));
        assertThat(store.findByToken(new OpaqueToken("s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000002:"
                + "B".repeat(43)))).isEmpty();
        // The right session named with a wrong secret is "no session"; by lookup the BFF still reads it.
        OpaqueToken wrongSecret = OpaqueToken.of(TOKEN.channel(), TOKEN.sessionId(), "B".repeat(43));
        assertThat(store.findByToken(wrongSecret)).isEmpty();
        assertThat(store.findByLookup(lookup)).isPresent();
    }

    @Test
    void aSessionIdInUseIsNeverOverwritten() {
        store.create(session, TOKEN);
        OpaqueToken sameIdOtherSecret = OpaqueToken.of(TOKEN.channel(), TOKEN.sessionId(), "B".repeat(43));

        assertThatThrownBy(() -> store.create(session, sameIdOtherSecret)).isInstanceOf(IllegalStateException.class);

        assertThat(store.findByToken(TOKEN)).isPresent();
        assertThat(store.findByToken(sameIdOtherSecret)).isEmpty();
    }

    @Test
    void aSaveSucceedsOnlyWhileTheStoreHoldsWhatTheCallerRead() {
        store.create(session, TOKEN);
        SessionLookup lookup = keys.lookupOf(TOKEN);
        StoredSession read = store.findByLookup(lookup).orElseThrow();
        Instant admitted = Instant.now();
        Session extended = session.extend(admitted, admitted, POLICY);

        Session saved = store.saveIfCurrent(read, extended).orElseThrow();
        assertThat(saved.sessionVersion()).isEqualTo(1);
        assertThat(saved.idleExpiresAt()).isEqualTo(extended.idleExpiresAt());
        assertThat(redis.getExpire(keys.forLookup(lookup), TimeUnit.SECONDS)).isBetween(14 * 60L + 50, 15 * 60L);

        // A writer holding what it read before the save loses.
        assertThat(store.saveIfCurrent(read, extended)).isEmpty();
        assertThat(store.findByLookup(lookup).orElseThrow().session().sessionVersion()).isEqualTo(1);
        // A writer holding the current record wins; the digest it opens with stays.
        StoredSession current = store.findByLookup(lookup).orElseThrow();
        assertThat(store.saveIfCurrent(current, saved.extend(admitted, admitted, POLICY))).isPresent();
        assertThat(store.findByLookup(lookup).orElseThrow().session().sessionVersion()).isEqualTo(2);
        assertThat(store.findByToken(TOKEN)).isPresent();
        // The same version with another secret digest is not the stored record either.
        StoredSession otherDigest = new StoredSession(lookup, store.findByLookup(lookup).orElseThrow().session(),
                SessionSecretDigest.of("B".repeat(43)));
        assertThat(store.saveIfCurrent(otherDigest, saved.extend(admitted, admitted, POLICY))).isEmpty();
    }

    @Test
    void ofManyWritersHoldingTheSameSessionOnlyOneSaves() throws Exception {
        store.create(session, TOKEN);
        StoredSession read = store.findByLookup(keys.lookupOf(TOKEN)).orElseThrow();
        Instant admitted = Instant.now();
        int writers = 16;
        ExecutorService pool = Executors.newFixedThreadPool(writers);
        try {
            List<Callable<Boolean>> saves = new ArrayList<>();
            for (int writer = 0; writer < writers; writer++) {
                saves.add(() -> store.saveIfCurrent(read, session.extend(admitted, admitted, POLICY)).isPresent());
            }
            long winners = 0;
            for (Future<Boolean> saved : pool.invokeAll(saves)) {
                if (saved.get(10, TimeUnit.SECONDS)) {
                    winners++;
                }
            }
            assertThat(winners).isEqualTo(1);
            assertThat(store.findByToken(TOKEN).orElseThrow().session().sessionVersion()).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void deleteRemovesOnceAndASaveAfterwardsDoesNotBringTheSessionBack() {
        store.create(session, TOKEN);
        SessionLookup lookup = keys.lookupOf(TOKEN);
        StoredSession read = store.findByLookup(lookup).orElseThrow();

        // One atomic DEL: the first caller removes the key, every later one learns it is gone.
        assertThat(store.delete(lookup)).isTrue();
        assertThat(store.findByToken(TOKEN)).isEmpty();
        assertThat(store.delete(lookup)).isFalse();

        Instant admitted = Instant.now();
        assertThat(store.saveIfCurrent(read, session.extend(admitted, admitted, POLICY))).isEmpty();
        assertThat(redis.hasKey(keys.forLookup(lookup))).isFalse();
    }

    @Test
    void aMalformedRecordIsNoSession() {
        String key = keys.forLookup(keys.lookupOf(TOKEN));
        redis.opsForValue().set(key, "{\"schemaVersion\":1,\"customerId\":\"90359\"}");
        assertThat(store.findByToken(TOKEN)).isEmpty();
        assertThat(store.findByLookup(keys.lookupOf(TOKEN))).isEmpty();
    }

    /** Each write is one command on the shared connection: it needs none of the pool's WATCH connections. */
    @Test
    void aWriteNeedsNoConnectionOfItsOwn() throws Exception {
        LettuceConnectionFactory pooledConnections = PooledValkey.connections(VALKEY, 2, Duration.ofMillis(100));
        try {
            StringRedisTemplate pooledRedis = new StringRedisTemplate(pooledConnections);
            ValkeySessionAdapter pooledStore = storeOn(pooledRedis);
            pooledRedis.hasKey("opens-the-shared-connection");

            try (PooledValkey.HeldConnection onlyWriteConnection = PooledValkey.holdWriteConnection(pooledRedis)) {
                pooledStore.create(session, TOKEN);
                StoredSession read = pooledStore.findByToken(TOKEN).orElseThrow();
                Instant admitted = Instant.now();
                assertThat(pooledStore.saveIfCurrent(read, session.extend(admitted, admitted, POLICY))).isPresent();
                assertThat(pooledStore.delete(keys.lookupOf(TOKEN))).isTrue();
                assertThat(PooledValkey.connectionIdsOf(pooledRedis)).hasSize(2); // the shared one and the held one
            }
        } finally {
            pooledConnections.destroy();
        }
    }

    @Test
    void aStoreOutageIsUnavailable() {
        LettuceConnectionFactory dead = new LettuceConnectionFactory(new RedisStandaloneConfiguration("127.0.0.1", 1));
        dead.afterPropertiesSet();
        try {
            ValkeySessionAdapter broken = storeOn(new StringRedisTemplate(dead));
            assertThatThrownBy(() -> broken.findByToken(TOKEN)).isInstanceOf(RepositoryUnavailableException.class);
        } finally {
            dead.destroy();
        }
    }

    private static ValkeySessionAdapter storeOn(StringRedisTemplate template) {
        return new ValkeySessionAdapter(new ValkeyRecordCommands(template), new SessionKeys(),
                new SessionJsonCodec(SessionJsonCodec.strictJson()));
    }
}
