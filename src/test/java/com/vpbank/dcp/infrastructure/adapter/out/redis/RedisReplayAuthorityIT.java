package com.vpbank.dcp.infrastructure.adapter.out.redis;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordReplayAttempt;
import com.vpbank.dcp.core.port.out.password.PasswordReplayResult;
import com.vpbank.dcp.core.port.out.replay.ReplayAttempt;
import com.vpbank.dcp.core.port.out.replay.ReplayReservation;
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
            "redis@sha256:3b73847e72874be07e6657b129a94761662b79bc0f679273757d4218573b2a98")
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
                new RequestKeyThumbprint(digest(1)), digest(2),
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
