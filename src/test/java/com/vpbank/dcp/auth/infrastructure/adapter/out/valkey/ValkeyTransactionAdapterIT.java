package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
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

/** Transactions of any flow on a real Valkey: one record per kind and ID, TTL, compare-and-set saves, one-shot removal. */
@Testcontainers
class ValkeyTransactionAdapterIT {
    @Container
    static final GenericContainer<?> VALKEY = new GenericContainer<>(ValkeyImage.underTest()).withExposedPorts(6379);

    /** A payload of one flow; another flow's payload has a different shape. */
    record Enrollment(String owner, int attempts, String secret) {
    }

    record Credential(String owner, long rotation) {
    }

    private static final TransactionKind<Enrollment> ENROLLMENT = new TransactionKind<>("enrollment", Enrollment.class);
    private static final TransactionKind<Credential> CREDENTIAL = new TransactionKind<>("credential", Credential.class);
    private static final String TABLET = "MOBILE:90359:tablet-2";
    private static final String TABLET_KEY = "tx:v2:enrollment:" + TABLET;

    private static LettuceConnectionFactory connections;
    private static StringRedisTemplate redis;
    private final ValkeyTransactionAdapter store = storeOn(redis);

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
        assertThat(store.createIfAbsent(CREDENTIAL.open(TABLET, deadline(), new Credential("s-1", 1)))).isTrue();
        assertThat(store.find(ENROLLMENT, TABLET)).contains(first);

        // One JSON STRING, forgotten by the server at the deadline.
        assertThat(redis.type(TABLET_KEY)).isEqualTo(DataType.STRING);
        assertThat(redis.opsForValue().get(TABLET_KEY)).startsWith("{\"schemaVersion\":2,\"purpose\":\"enrollment\",")
                .contains("\"version\":0").contains("\"secret\":\"k1\"");
        assertThat(redis.getExpire(TABLET_KEY, TimeUnit.SECONDS)).isBetween(590L, 600L);
    }

    @Test
    void overwriteReplacesWhateverTheIdHeldAndStartsAtVersionZero() {
        CacheTransaction<Enrollment> first = enrollment("s-1");
        store.createIfAbsent(first);
        store.saveIfCurrent(first, new Enrollment("s-1", 1, "k1")).orElseThrow();

        CacheTransaction<Enrollment> replacement = enrollment("s-2");
        store.overwrite(replacement);

        assertThat(store.find(ENROLLMENT, TABLET)).contains(replacement);
        assertThat(redis.getExpire(TABLET_KEY, TimeUnit.SECONDS)).isBetween(590L, 600L);
        assertThatThrownBy(() -> store.overwrite(replacement.next(new Enrollment("s-2", 1, "k1"))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aSaveSucceedsOnlyWhileTheStoreHoldsWhatTheCallerRead() {
        CacheTransaction<Enrollment> started = enrollment("s-1");
        store.createIfAbsent(started);

        Optional<CacheTransaction<Enrollment>> counted = store.saveIfCurrent(started, new Enrollment("s-1", 1, "k1"));
        assertThat(counted).hasValueSatisfying(saved -> {
            assertThat(saved.version()).isEqualTo(1);
            assertThat(saved.payload().attempts()).isEqualTo(1);
        });
        assertThat(store.saveIfCurrent(started, new Enrollment("s-1", 1, "k1"))).isEmpty(); // version 0 is stale

        CacheTransaction<Enrollment> proven = store.saveIfCurrent(counted.get(), new Enrollment("s-1", 1, "k2")).orElseThrow();
        assertThat(proven.version()).isEqualTo(2);
        assertThat(store.find(ENROLLMENT, TABLET)).contains(proven);
        assertThat(redis.getExpire(TABLET_KEY, TimeUnit.SECONDS)).isBetween(590L, 600L);

        // The right version is not enough: the caller must hold the stored transaction itself.
        CacheTransaction<Enrollment> sameVersionOtherPayload =
                new CacheTransaction<>(ENROLLMENT, TABLET, proven.expiresAt(), 2, new Enrollment("s-9", 1, "k2"));
        assertThat(store.saveIfCurrent(sameVersionOtherPayload, new Enrollment("s-9", 2, "k2"))).isEmpty();
        assertThat(store.deleteIfCurrent(sameVersionOtherPayload)).isFalse();
        assertThat(store.find(ENROLLMENT, TABLET)).contains(proven);
    }

    @Test
    void ofTwoWritersHoldingTheSameTransactionOnlyOneSaves() throws Exception {
        CacheTransaction<Enrollment> started = enrollment("s-1");
        store.createIfAbsent(started);
        int writers = 16;
        ExecutorService pool = Executors.newFixedThreadPool(writers);
        try {
            List<Callable<Boolean>> saves = new ArrayList<>();
            for (int writer = 0; writer < writers; writer++) {
                Enrollment mine = new Enrollment("s-1", writer + 1, "k1");
                saves.add(() -> store.saveIfCurrent(started, mine).isPresent());
            }
            long winners = 0;
            for (Future<Boolean> saved : pool.invokeAll(saves)) {
                if (saved.get(10, TimeUnit.SECONDS)) {
                    winners++;
                }
            }
            assertThat(winners).isEqualTo(1);
            assertThat(store.find(ENROLLMENT, TABLET).orElseThrow().version()).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void removalIsOneShotAndOnlyForTheStoredTransaction() {
        CacheTransaction<Enrollment> started = enrollment("s-1");
        store.createIfAbsent(started);
        CacheTransaction<Enrollment> counted = store.saveIfCurrent(started, new Enrollment("s-1", 1, "k1")).orElseThrow();

        assertThat(store.deleteIfCurrent(started)).isFalse(); // stale
        assertThat(store.find(ENROLLMENT, TABLET)).isPresent();
        assertThat(store.deleteIfCurrent(counted)).isTrue();
        assertThat(redis.hasKey(TABLET_KEY)).isFalse(); // the claim's tombstone is removed right away
        assertThat(store.deleteIfCurrent(counted)).isFalse(); // the second claimant loses
        assertThat(store.find(ENROLLMENT, TABLET)).isEmpty();
        assertThat(store.saveIfCurrent(counted, new Enrollment("s-1", 2, "k1"))).isEmpty(); // gone

        assertThat(store.createIfAbsent(enrollment("s-2"))).isTrue(); // the ID may start again
    }

    @Test
    void aCorruptedRecordIsNoTransactionAndCannotBeSavedOver() {
        CacheTransaction<Enrollment> started = enrollment("s-1");
        store.createIfAbsent(started);
        String stored = redis.opsForValue().get(TABLET_KEY);
        redis.opsForValue().set(TABLET_KEY, stored.replace("\"secret\":\"k1\"", "\"secret\":\"k1\",\"x\":1"));

        assertThat(store.find(ENROLLMENT, TABLET)).isEmpty();
        assertThat(store.saveIfCurrent(started, new Enrollment("s-1", 1, "k1"))).isEmpty();
        assertThat(store.deleteIfCurrent(started)).isFalse();

        // A tombstone a crashed remover left behind is no transaction either, and nothing is written over it.
        redis.opsForValue().set(TABLET_KEY, "");
        assertThat(store.find(ENROLLMENT, TABLET)).isEmpty();
        assertThat(store.saveIfCurrent(started, new Enrollment("s-1", 1, "k1"))).isEmpty();
        assertThat(store.deleteIfCurrent(started)).isFalse();
    }

    @Test
    void aTransactionAlreadyPastItsDeadlineIsNotKept() {
        CacheTransaction<Enrollment> expired = ENROLLMENT.open(TABLET, Instant.now().minusSeconds(1),
                new Enrollment("s-1", 0, "k1"));

        store.createIfAbsent(expired);

        assertThat(store.find(ENROLLMENT, TABLET)).isEmpty();
    }

    @Test
    void aStoreThatDoesNotAnswerIsUnavailable() {
        LettuceConnectionFactory deadConnections = new LettuceConnectionFactory(new RedisStandaloneConfiguration("127.0.0.1", 1));
        deadConnections.afterPropertiesSet();
        try {
            ValkeyTransactionAdapter deadStore = storeOn(new StringRedisTemplate(deadConnections));
            CacheTransaction<Enrollment> started = enrollment("s-1");
            assertThatThrownBy(() -> deadStore.find(ENROLLMENT, TABLET)).isInstanceOf(RepositoryUnavailableException.class);
            assertThatThrownBy(() -> deadStore.createIfAbsent(started)).isInstanceOf(RepositoryUnavailableException.class);
            assertThatThrownBy(() -> deadStore.saveIfCurrent(started, new Enrollment("s-1", 1, "k1")))
                    .isInstanceOf(RepositoryUnavailableException.class);
            assertThatThrownBy(() -> deadStore.deleteIfCurrent(started)).isInstanceOf(RepositoryUnavailableException.class);
        } finally {
            deadConnections.destroy();
        }
    }

    private static ValkeyTransactionAdapter storeOn(StringRedisTemplate template) {
        return new ValkeyTransactionAdapter(new ValkeyRecordCommands(template), new TransactionKeys(),
                new TransactionJsonCodec(TransactionJsonCodec.strictPayloadJson()));
    }

    private static CacheTransaction<Enrollment> enrollment(String session) {
        return ENROLLMENT.open(TABLET, deadline(), new Enrollment(session, 0, "k1"));
    }

    private static Instant deadline() {
        return Instant.now().plusSeconds(600).truncatedTo(ChronoUnit.MILLIS); // the HASH keeps milliseconds
    }
}
