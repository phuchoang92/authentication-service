package com.vpbank.dcp.auth.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.port.out.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.StoredSession;
import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
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

/** The adapter against a real Valkey: key layout, TTL, strict decode, and the WATCH/MULTI/EXEC compare-and-set. */
@Testcontainers
class ValkeySessionAdapterIT {
    @Container
    static final GenericContainer<?> VALKEY = new GenericContainer<>("valkey/valkey:9.1").withExposedPorts(6379);
    private static final OpaqueToken TOKEN = new OpaqueToken("k1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    private static final SessionPolicy POLICY = new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20),
            Duration.ofSeconds(30));

    private static LettuceConnectionFactory connections;
    private static StringRedisTemplate redis;
    private final SessionKeys keys = new SessionKeys(Map.of("k1", new byte[32]));
    private final ValkeySessionAdapter store = new ValkeySessionAdapter(redis, keys);
    /** Stored as milliseconds (contract 16), so the fixture must not carry finer precision. */
    private final Instant now = Instant.now().minusSeconds(5).truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
    private final Session session = Session.start(SessionId.random(), new CustomerId("90359"), new DeviceId("dev-1"),
            Channel.MOBILE, now, POLICY);

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
    void createsTheHashUnderTheKeyedLookupWithTheIdleDeadlineAsTtl() {
        store.create(session, TOKEN);

        SessionLookup lookup = keys.lookupOf(TOKEN);
        String key = "session:v1:k1:" + lookup.digest();
        assertThat(redis.hasKey(key)).isTrue();
        assertThat(redis.opsForHash().entries(key)).doesNotContainKey("token").containsEntry("customerId", "90359");
        long ttl = redis.getExpire(key, TimeUnit.SECONDS);
        assertThat(ttl).isBetween(14 * 60L, 15 * 60L);
        assertThat(store.findByToken(TOKEN)).map(StoredSession::session).contains(session);
        assertThat(store.findByLookup(lookup)).map(StoredSession::session).contains(session);
        assertThat(store.findByToken(new OpaqueToken("k1.BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))).isEmpty();
    }

    @Test
    void saveIsCompareAndSetOnTheStoredVersion() {
        store.create(session, TOKEN);
        SessionLookup lookup = keys.lookupOf(TOKEN);
        Instant admitted = Instant.now();
        Session extended = session.extend(admitted, admitted, POLICY);

        Session saved = store.saveIfCurrent(lookup, extended).orElseThrow();
        assertThat(saved.sessionVersion()).isEqualTo(1);
        assertThat(saved.idleExpiresAt()).isEqualTo(extended.idleExpiresAt());
        assertThat(redis.getExpire(keys.forLookup(lookup), TimeUnit.SECONDS)).isBetween(14 * 60L + 50, 15 * 60L);

        // A writer holding the old version loses.
        assertThat(store.saveIfCurrent(lookup, extended)).isEmpty();
        assertThat(store.findByLookup(lookup).orElseThrow().session().sessionVersion()).isEqualTo(1);
        // A writer holding the current version wins.
        assertThat(store.saveIfCurrent(lookup, saved.extend(admitted, admitted, POLICY))).isPresent();
        assertThat(store.findByLookup(lookup).orElseThrow().session().sessionVersion()).isEqualTo(2);
    }

    @Test
    void deleteIsCompareAndSetAndAbsentAfterwards() {
        store.create(session, TOKEN);
        SessionLookup lookup = keys.lookupOf(TOKEN);

        assertThat(store.deleteIfCurrent(lookup, session.withSessionVersion(7))).isFalse();
        assertThat(store.deleteIfCurrent(lookup, session)).isTrue();
        assertThat(store.findByToken(TOKEN)).isEmpty();
        assertThat(store.deleteIfCurrent(lookup, session)).isFalse();
    }

    @Test
    void aMalformedHashIsNoSession() {
        String key = keys.forLookup(keys.lookupOf(TOKEN));
        redis.opsForHash().putAll(key, Map.of("schemaVersion", "1", "customerId", "90359"));
        assertThat(store.findByToken(TOKEN)).isEmpty();
    }

    @Test
    void aStoreOutageIsUnavailable() {
        LettuceConnectionFactory dead = new LettuceConnectionFactory(new RedisStandaloneConfiguration("127.0.0.1", 1));
        dead.afterPropertiesSet();
        try {
            ValkeySessionAdapter broken = new ValkeySessionAdapter(new StringRedisTemplate(dead), keys);
            assertThatThrownBy(() -> broken.findByToken(TOKEN)).isInstanceOf(RepositoryUnavailableException.class);
        } finally {
            dead.destroy();
        }
    }
}
