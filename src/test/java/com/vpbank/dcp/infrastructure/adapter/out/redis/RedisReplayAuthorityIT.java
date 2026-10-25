package com.vpbank.dcp.infrastructure.adapter.out.redis;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.password.PasswordProofIds;
import com.vpbank.dcp.core.password.PasswordReplayAttempt;
import com.vpbank.dcp.core.password.PasswordReplayResult;
import com.vpbank.dcp.core.replay.ReplayAttempt;
import com.vpbank.dcp.core.replay.ReplayReservation;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.PasswordProofReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.RuntimeKeys;
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

@Testcontainers
class RedisReplayAuthorityIT {

    private static final AuthorityScope SCOPE = new AuthorityScope("bank-dev-neo");

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(
            "valkey/valkey@sha256:418652cfb58ef879d4978c33553735d7147016032d5aefaa14c828e611eb9dfd")
            .withExposedPorts(6379);

    private LettuceConnectionFactory factory;
    private StringRedisTemplate redis;
    private RedisServerIdentity identity;

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
    }

    @AfterEach
    void disconnect() {
        factory.destroy();
    }

    @Test
    void sameDpopProofIsRejectedAcrossReplicas() {
        ReplayKeys keys = new ReplayKeys(SCOPE);
        RedisReplayProtection first = new RedisReplayProtection(redis, identity, keys);
        RedisReplayProtection second = new RedisReplayProtection(redis, identity, keys);
        ReplayAttempt attempt = new ReplayAttempt(new RequestKeyThumbprint(digest(1)),
                digest(2), identity.currentGeneration().orElseThrow());

        assertThat(first.reserve(attempt)).isEqualTo(ReplayReservation.RESERVED);
        assertThat(second.reserve(attempt)).isEqualTo(ReplayReservation.REPLAYED);
        assertThat(redis.getExpire(keys.forDpop(attempt.requestKey(), attempt.proofIdDigest())))
                .isBetween(1L, 120L);
    }

    @Test
    void passwordProofMarkersRejectARepeatedRequest() {
        RedisPasswordProofReplay first = passwordReplay();
        RedisPasswordProofReplay second = passwordReplay();
        PasswordReplayAttempt attempt = new PasswordReplayAttempt(
                UUID.randomUUID(), new RequestKeyThumbprint(digest(1)), digest(2),
                new PasswordProofIds(digest(3), digest(4), digest(5)));

        UUID generation = identity.currentGeneration().orElseThrow();
        assertThat(first.reserve(attempt)).isEqualTo(new PasswordReplayResult.Reserved(generation));
        assertThat(second.reserve(attempt)).isInstanceOf(PasswordReplayResult.Replayed.class);
    }

    @Test
    void staleRedisGenerationCannotReserve() {
        RedisReplayProtection replay = new RedisReplayProtection(
                redis, identity, new ReplayKeys(SCOPE));
        ReplayAttempt attempt = new ReplayAttempt(new RequestKeyThumbprint(digest(1)),
                digest(2), UUID.randomUUID());

        assertThat(replay.reserve(attempt)).isEqualTo(ReplayReservation.AUTHORITY_CLOSED);
    }

    private RedisPasswordProofReplay passwordReplay() {
        return new RedisPasswordProofReplay(redis, identity, new ReplayKeys(SCOPE),
                new PasswordProofReplayKeys(SCOPE));
    }

    private Digest32 digest(int marker) {
        byte[] bytes = new byte[32];
        bytes[0] = (byte) marker;
        return Digest32.fromBytes(bytes);
    }
}
