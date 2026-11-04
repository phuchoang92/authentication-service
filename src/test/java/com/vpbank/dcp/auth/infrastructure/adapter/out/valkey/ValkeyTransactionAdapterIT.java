package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
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

/** Transactions of any flow on a real Valkey: one record per kind and ID, TTL, compare-and-set saves, one-shot removal. */
@Testcontainers
class ValkeyTransactionAdapterIT {
    @Container
    static final GenericContainer<?> VALKEY = new GenericContainer<>("valkey/valkey:9.1").withExposedPorts(6379);

    /** A payload of one flow; another flow's payload has a different shape. */
    record Enrollment(String owner, int attempts, String secret) {
    }

    record Credential(String owner, long rotation) {
    }

    private static final TransactionKind<Enrollment> ENROLLMENT = new TransactionKind<>("enrollment", Enrollment.class);
    private static final TransactionKind<Credential> CREDENTIAL = new TransactionKind<>("credential", Credential.class);
    private static final String TABLET = "MOBILE:90359:tablet-2";

    private static LettuceConnectionFactory connections;
    private static StringRedisTemplate redis;
    private final ValkeyTransactionAdapter store = new ValkeyTransactionAdapter(redis, new TransactionKeys(),
            new TransactionHashCodec(TransactionHashCodec.strictPayloadJson()));

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
    void oneRecordPerKindAndIdUnderItsKeyUntilTheDeadline() {
        CacheTransaction<Enrollment> first = enrollment("s-1");
        CacheTransaction<Enrollment> secondLogin = enrollment("s-2");

        assertThat(store.createIfAbsent(first)).isTrue();
        assertThat(store.createIfAbsent(secondLogin)).isFalse(); // nothing is overwritten

        assertThat(store.find(ENROLLMENT, TABLET)).contains(first);
        assertThat(store.find(ENROLLMENT, "MOBILE:90359:phone-1")).isEmpty();
        // Another flow with the same ID is another record; the enrollment is not readable as a credential.
        assertThat(store.find(CREDENTIAL, TABLET)).isEmpty();
        assertThat(store.createIfAbsent(CacheTransaction.open(CREDENTIAL, TABLET, deadline(), new Credential("s-1", 1)))).isTrue();
        assertThat(store.find(ENROLLMENT, TABLET)).contains(first);

        String key = "tx:v1:enrollment:" + TABLET;
        assertThat(redis.hasKey(key)).isTrue();
        assertThat(redis.opsForHash().get(key, "payload").toString()).contains("\"secret\":\"k1\"");
        assertThat(redis.getExpire(key, TimeUnit.SECONDS)).isBetween(590L, 600L);
    }

    @Test
    void aSaveIsCompareAndSetAndReplacesTheWholeRecord() {
        CacheTransaction<Enrollment> started = enrollment("s-1");
        store.createIfAbsent(started);

        Optional<CacheTransaction<Enrollment>> counted = store.saveIfCurrent(started.withPayload(new Enrollment("s-1", 1, "k1")));
        assertThat(counted).hasValueSatisfying(saved -> {
            assertThat(saved.version()).isEqualTo(1);
            assertThat(saved.payload().attempts()).isEqualTo(1);
        });
        assertThat(store.saveIfCurrent(started.withPayload(new Enrollment("s-1", 1, "k1")))).isEmpty(); // version 0 is stale

        CacheTransaction<Enrollment> proven = store.saveIfCurrent(counted.get().withPayload(new Enrollment("s-1", 1, "k2")))
                .orElseThrow();
        assertThat(proven.version()).isEqualTo(2);
        assertThat(store.find(ENROLLMENT, TABLET)).contains(proven);
        assertThat(redis.getExpire("tx:v1:enrollment:" + TABLET, TimeUnit.SECONDS)).isBetween(590L, 600L);

        // Another transaction of the same ID at version 0 is not the stored one.
        assertThat(store.saveIfCurrent(enrollment("s-2"))).isEmpty();
    }

    @Test
    void removalIsOneShotAndOnlyForTheCurrentVersion() {
        CacheTransaction<Enrollment> started = enrollment("s-1");
        store.createIfAbsent(started);
        CacheTransaction<Enrollment> counted = store.saveIfCurrent(started.withPayload(new Enrollment("s-1", 1, "k1"))).orElseThrow();

        assertThat(store.deleteIfCurrent(started)).isFalse(); // stale version
        assertThat(store.find(ENROLLMENT, TABLET)).isPresent();
        assertThat(store.deleteIfCurrent(counted)).isTrue();
        assertThat(store.deleteIfCurrent(counted)).isFalse(); // the second claimant loses
        assertThat(store.find(ENROLLMENT, TABLET)).isEmpty();

        assertThat(store.createIfAbsent(enrollment("s-2"))).isTrue(); // the ID may start again
    }

    @Test
    void aCorruptedRecordIsNoTransactionAndCannotBeSavedOver() {
        CacheTransaction<Enrollment> started = enrollment("s-1");
        store.createIfAbsent(started);
        redis.opsForHash().put("tx:v1:enrollment:" + TABLET, "payload", "{\"owner\":\"s-1\",\"attempts\":0,\"secret\":\"k1\",\"x\":1}");

        assertThat(store.find(ENROLLMENT, TABLET)).isEmpty();
        assertThat(store.saveIfCurrent(started.withPayload(new Enrollment("s-1", 1, "k1")))).isEmpty();
        assertThat(store.deleteIfCurrent(started)).isFalse();
    }

    @Test
    void aStoreThatDoesNotAnswerIsUnavailable() {
        LettuceConnectionFactory deadConnections = new LettuceConnectionFactory(new RedisStandaloneConfiguration("127.0.0.1", 1));
        deadConnections.afterPropertiesSet();
        try {
            ValkeyTransactionAdapter deadStore = new ValkeyTransactionAdapter(new StringRedisTemplate(deadConnections),
                    new TransactionKeys(), new TransactionHashCodec(TransactionHashCodec.strictPayloadJson()));
            assertThatThrownBy(() -> deadStore.find(ENROLLMENT, TABLET)).isInstanceOf(RepositoryUnavailableException.class);
            assertThatThrownBy(() -> deadStore.createIfAbsent(enrollment("s-1"))).isInstanceOf(RepositoryUnavailableException.class);
        } finally {
            deadConnections.destroy();
        }
    }

    private static CacheTransaction<Enrollment> enrollment(String session) {
        return CacheTransaction.open(ENROLLMENT, TABLET, deadline(), new Enrollment(session, 0, "k1"));
    }

    private static Instant deadline() {
        return Instant.now().plusSeconds(600).truncatedTo(ChronoUnit.MILLIS); // the HASH keeps milliseconds
    }
}
