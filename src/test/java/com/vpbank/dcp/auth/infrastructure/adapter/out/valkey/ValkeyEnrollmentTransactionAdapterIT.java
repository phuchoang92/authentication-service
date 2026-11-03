package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
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

/** Primary enrollments in flight on a real Valkey: one per device, TTL, compare-and-set saves and one-shot removal. */
@Testcontainers
class ValkeyEnrollmentTransactionAdapterIT {
    @Container
    static final GenericContainer<?> VALKEY = new GenericContainer<>("valkey/valkey:9.1").withExposedPorts(6379);
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final DeviceId TABLET = new DeviceId("tablet-2");

    private static LettuceConnectionFactory connections;
    private static StringRedisTemplate redis;
    private final EnrollmentTransactionKeys keys = new EnrollmentTransactionKeys();
    private final ValkeyEnrollmentTransactionAdapter store = new ValkeyEnrollmentTransactionAdapter(redis, keys);

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
    void aDeviceHasOneTransactionUnderItsKeyUntilTheDeadline() {
        EnrollmentTransaction first = startedBy(SessionId.random());
        EnrollmentTransaction secondLogin = startedBy(SessionId.random());

        assertThat(store.createIfAbsent(first)).isTrue();
        assertThat(store.createIfAbsent(secondLogin)).isFalse(); // nothing is overwritten

        assertThat(store.find(ALICE, Channel.MOBILE, TABLET)).contains(first);
        assertThat(store.find(ALICE, Channel.MOBILE, new DeviceId("phone-1"))).isEmpty();
        assertThat(store.find(ALICE, Channel.WEB, TABLET)).isEmpty();
        assertThat(store.find(new CustomerId("77777"), Channel.MOBILE, TABLET)).isEmpty();

        String key = "enrollment-tx:v1:MOBILE:90359:tablet-2";
        assertThat(redis.hasKey(key)).isTrue();
        assertThat(redis.getExpire(key, TimeUnit.SECONDS)).isBetween(590L, 600L);
    }

    @Test
    void aSaveIsCompareAndSetAndReplacesTheWholeRecord() {
        EnrollmentTransaction knownDevice = startedBy(SessionId.random()).toBuilder()
                .targetDeviceId(TrustedDeviceId.random())
                .build();
        store.createIfAbsent(knownDevice);

        Optional<EnrollmentTransaction> counted = store.saveIfCurrent(knownDevice.countVerifyAttempt());
        assertThat(counted).hasValueSatisfying(saved -> {
            assertThat(saved.version()).isEqualTo(1);
            assertThat(saved.verifyAttempts()).isEqualTo(1);
        });
        assertThat(store.saveIfCurrent(knownDevice.countVerifyAttempt())).isEmpty(); // version 0 is stale now

        // The stored record is exactly the saved value: a field the new value lacks does not linger.
        EnrollmentTransaction withoutTarget = counted.get().toBuilder().targetDeviceId(null).build();
        EnrollmentTransaction verified = store.saveIfCurrent(withoutTarget.markMfaRequired("mfa-1")).orElseThrow();
        assertThat(verified.version()).isEqualTo(2);
        EnrollmentTransaction stored = store.find(ALICE, Channel.MOBILE, TABLET).orElseThrow();
        assertThat(stored).isEqualTo(verified);
        assertThat(stored.state()).isEqualTo(EnrollmentState.MFA_REQUIRED);
        assertThat(stored.targetDeviceId()).isNull();
        assertThat(redis.getExpire("enrollment-tx:v1:MOBILE:90359:tablet-2", TimeUnit.SECONDS)).isBetween(590L, 600L);

        // Another transaction of the same device at version 0 is not the stored one.
        assertThat(store.saveIfCurrent(startedBy(SessionId.random()))).isEmpty();
    }

    @Test
    void removalIsOneShotAndOnlyForTheCurrentVersion() {
        EnrollmentTransaction started = startedBy(SessionId.random());
        store.createIfAbsent(started);
        EnrollmentTransaction counted = store.saveIfCurrent(started.countVerifyAttempt()).orElseThrow();

        assertThat(store.deleteIfCurrent(started)).isFalse(); // stale version
        assertThat(store.find(ALICE, Channel.MOBILE, TABLET)).isPresent();
        assertThat(store.deleteIfCurrent(counted)).isTrue();
        assertThat(store.deleteIfCurrent(counted)).isFalse(); // the second claimant loses
        assertThat(store.find(ALICE, Channel.MOBILE, TABLET)).isEmpty();

        // The device may start again once the old transaction is gone.
        assertThat(store.createIfAbsent(startedBy(SessionId.random()))).isTrue();
    }

    @Test
    void aCorruptedRecordIsNoTransactionAndCannotBeSavedOver() {
        EnrollmentTransaction started = startedBy(SessionId.random());
        store.createIfAbsent(started);
        redis.opsForHash().put("enrollment-tx:v1:MOBILE:90359:tablet-2", "state", "COMPLETED");

        assertThat(store.find(ALICE, Channel.MOBILE, TABLET)).isEmpty();
        assertThat(store.saveIfCurrent(started.countVerifyAttempt())).isEmpty();
        assertThat(store.deleteIfCurrent(started)).isFalse();
    }

    @Test
    void aStoreThatDoesNotAnswerIsUnavailable() {
        LettuceConnectionFactory deadConnections = new LettuceConnectionFactory(new RedisStandaloneConfiguration("127.0.0.1", 1));
        deadConnections.afterPropertiesSet();
        try {
            ValkeyEnrollmentTransactionAdapter deadStore =
                    new ValkeyEnrollmentTransactionAdapter(new StringRedisTemplate(deadConnections), keys);
            assertThatThrownBy(() -> deadStore.find(ALICE, Channel.MOBILE, TABLET))
                    .isInstanceOf(RepositoryUnavailableException.class);
            assertThatThrownBy(() -> deadStore.createIfAbsent(startedBy(SessionId.random())))
                    .isInstanceOf(RepositoryUnavailableException.class);
        } finally {
            deadConnections.destroy();
        }
    }

    private static EnrollmentTransaction startedBy(SessionId sessionId) {
        AdmittedSession tabletSession = new AdmittedSession(sessionId, ALICE, Channel.MOBILE, TABLET,
                SessionStatus.NEED_TRUSTED_DEVICE);
        return EnrollmentTransaction.keyExchange(
                EnrollmentId.random(),
                tabletSession,
                null,
                "{dev}",
                DevicePlatform.IOS,
                "{srv-pub}",
                "{srv-priv}",
                "digest",
                Instant.now().plusSeconds(600).truncatedTo(ChronoUnit.MILLIS)); // the HASH keeps milliseconds
    }
}
