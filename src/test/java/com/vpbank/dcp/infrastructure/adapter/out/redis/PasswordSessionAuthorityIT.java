package com.vpbank.dcp.infrastructure.adapter.out.redis;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.out.session.PasswordSessionFacts;
import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;
import com.vpbank.dcp.core.port.out.session.SessionApplyResult;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.RuntimeKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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
class PasswordSessionAuthorityIT {

    private static final AuthorityScope SCOPE = new AuthorityScope("bank-session-it");

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(
            "redis@sha256:3b73847e72874be07e6657b129a94761662b79bc0f679273757d4218573b2a98")
            .withExposedPorts(6379);

    private LettuceConnectionFactory factory;
    private StringRedisTemplate redis;
    private RedisPasswordSessionAuthority authority;
    private UUID subjectId;
    private UUID bindingId;

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
        subjectId = UUID.randomUUID();
        bindingId = UUID.randomUUID();
        authority = new RedisPasswordSessionAuthority(redis, identity, SCOPE,
                Duration.ofSeconds(60), Clock.systemUTC());
    }

    @AfterEach
    void disconnect() {
        factory.destroy();
    }

    @Test
    void publishesSessionWithBoundOwnerAndExpiry() {
        PreparedPasswordSession candidate = candidate();
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.APPLIED);
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.ALREADY_APPLIED);
        assertThat(authority.deliverable(candidate)).isTrue();

        String key = new SessionKeys().forLookup(candidate.lookupVersion(),
                candidate.lookupDigest());
        assertThat(redis.opsForHash().get(key, "subjectId"))
                .isEqualTo(subjectId.toString());
        assertThat(redis.opsForHash().get(key, "deviceBindingId"))
                .isEqualTo(bindingId.toString());
        assertThat(redis.getExpire(key)).isPositive();
    }

    @Test
    void redisFlushClosesDeliveryAndCannotRecreateOldSession() {
        PreparedPasswordSession candidate = candidate();
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.APPLIED);
        redis.getConnectionFactory().getConnection().serverCommands().flushDb();

        assertThat(authority.currentGeneration()).isEmpty();
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.AUTHORITY_CLOSED);
        assertThat(authority.deliverable(candidate)).isFalse();
    }

    @Test
    void missingSessionExpiryDoesNotAuthorizeDelivery() {
        PreparedPasswordSession candidate = candidate();
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.APPLIED);
        String key = new SessionKeys().forLookup(candidate.lookupVersion(),
                candidate.lookupDigest());
        redis.persist(key);

        assertThat(authority.deliverable(candidate)).isFalse();
    }

    private PreparedPasswordSession candidate() {
        Instant now = Instant.now();
        PasswordSessionFacts facts = new PasswordSessionFacts(UUID.randomUUID(),
                UUID.randomUUID(), subjectId, "neo-mobile", bindingId, digest(1),
                "{}", "{}", digest(2), 0, 0, 0, 1,
                now.plusSeconds(120), "NONE", false);
        return new PreparedPasswordSession(facts, UUID.randomUUID(), UUID.randomUUID(),
                authority.currentGeneration().orElseThrow(), new LookupKeyVersion("k1"),
                digest(3), digest(4), "encrypted-only", "signed-receipt",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                SessionDeadlines.createdAt(now), now.plusSeconds(120));
    }

    private Digest32 digest(int marker) {
        byte[] bytes = new byte[32];
        bytes[0] = (byte) marker;
        return Digest32.fromBytes(bytes);
    }
}
