package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.device.BindingId;
import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.domain.session.SessionAssurance;
import com.vpbank.dcp.core.port.out.session.SessionActivationSnapshot;
import com.vpbank.dcp.core.port.out.session.CustomerStatusFreshness;
import com.vpbank.dcp.core.port.out.session.SessionSecurityVersions;
import com.vpbank.dcp.core.port.out.session.SessionKeyBindings;
import com.vpbank.dcp.core.port.out.session.SessionActivationContext;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.session.SessionDelivery;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import com.vpbank.dcp.core.port.out.session.SessionCandidate;
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
class SessionAuthorityIT {

    private static final AuthorityScope SCOPE = new AuthorityScope("bank-session-it");

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(
            "redis@sha256:3b73847e72874be07e6657b129a94761662b79bc0f679273757d4218573b2a98")
            .withExposedPorts(6379);

    private LettuceConnectionFactory factory;
    private StringRedisTemplate redis;
    private RedisSessionAuthority authority;
    private SubjectId subjectId;
    private BindingId bindingId;

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
        subjectId = new SubjectId(UUID.randomUUID());
        bindingId = new BindingId(UUID.randomUUID());
        authority = new RedisSessionAuthority(redis, identity, SCOPE,
                Duration.ofSeconds(60), Clock.systemUTC());
    }

    @AfterEach
    void disconnect() {
        factory.destroy();
    }

    @Test
    void publishesSessionWithBoundOwnerAndExpiry() {
        PreparedSession candidate = candidate();
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.APPLIED);
        String key = new SessionKeys().forLookup(candidate.candidate().lookup().version(), candidate.candidate().lookup().digest());
        var original = redis.opsForHash().entries(key);
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.ALREADY_APPLIED);
        assertThat(redis.opsForHash().entries(key)).isEqualTo(original);
        assertThat(authority.deliverable(candidate)).isTrue();

        assertThat(redis.opsForHash().get(key, "subjectId"))
                .isEqualTo(subjectId.toString());
        assertThat(redis.opsForHash().get(key, "deviceBindingId"))
                .isEqualTo(bindingId.toString());
        assertThat(redis.opsForHash().get(key, "assurance")).isEqualTo(
                "{\"biometricEnforcement\":\"NOT_APPLICABLE\",\"devicePossession\":\"MFA_KEY_POSSESSION\",\"platformEvidence\":\"NONE\"}");
        assertThat(redis.getExpire(key)).isPositive();
    }

    @Test
    void serializesAssuranceSuppliedByTheAuthenticationSource() {
        var original = candidate();
        var old = original.snapshot();
        var snapshot = new SessionActivationSnapshot(old.context(), old.keys(),
                old.securityVersions(), old.customerStatus(),
                new SessionAssurance(SessionAssurance.DevicePossession.MFA_KEY_POSSESSION,
                        SessionAssurance.PlatformEvidence.NONE, SessionAssurance.BiometricEnforcement.CLIENT_ENFORCED),
                old.biometricLoginEnabled());
        var supplied = new PreparedSession(snapshot, original.candidate(), original.delivery(), original.deadlines());
        assertThat(authority.apply(supplied)).isEqualTo(SessionApplyResult.APPLIED);
        String key = new SessionKeys().forLookup(supplied.candidate().lookup().version(), supplied.candidate().lookup().digest());
        assertThat(redis.opsForHash().get(key, "assurance")).isEqualTo(
                "{\"biometricEnforcement\":\"CLIENT_ENFORCED\",\"devicePossession\":\"MFA_KEY_POSSESSION\",\"platformEvidence\":\"NONE\"}");
    }

    @Test
    void redisFlushClosesDeliveryAndCannotRecreateOldSession() {
        PreparedSession candidate = candidate();
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.APPLIED);
        redis.getConnectionFactory().getConnection().serverCommands().flushDb();

        assertThat(authority.currentGeneration()).isEmpty();
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.AUTHORITY_CLOSED);
        assertThat(authority.deliverable(candidate)).isFalse();
    }

    @Test
    void missingSessionExpiryDoesNotAuthorizeDelivery() {
        PreparedSession candidate = candidate();
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.APPLIED);
        String key = new SessionKeys().forLookup(candidate.candidate().lookup().version(),
                candidate.candidate().lookup().digest());
        redis.persist(key);

        assertThat(authority.deliverable(candidate)).isFalse();
    }

    @Test
    void revokedCandidateCannotBeDelivered() {
        PreparedSession candidate = candidate();
        assertThat(authority.apply(candidate)).isEqualTo(SessionApplyResult.APPLIED);

        assertThat(authority.revoke(candidate)).isTrue();
        assertThat(authority.deliverable(candidate)).isFalse();
    }

    private PreparedSession candidate() {
        Instant now = Instant.now();
        SessionActivationSnapshot snapshot = new SessionActivationSnapshot(
                new SessionActivationContext(UUID.randomUUID(), subjectId,
                        "neo-mobile", bindingId),
                new SessionKeyBindings(digest(1), "{}", "{}", digest(2)),
                new SessionSecurityVersions(0, 0, 0),
                new CustomerStatusFreshness(1, now.plusSeconds(120)),
                new SessionAssurance(SessionAssurance.DevicePossession.MFA_KEY_POSSESSION,
                        SessionAssurance.PlatformEvidence.NONE, SessionAssurance.BiometricEnforcement.NOT_APPLICABLE),
                false);
        return new PreparedSession(snapshot,
                new SessionCandidate(UUID.randomUUID(), UUID.randomUUID(), authority.currentGeneration().orElseThrow(),
                        new SessionTokenLookup(new LookupKeyVersion("k1"), digest(3)), digest(4)),
                new SessionDelivery("encrypted-only", "signed-receipt", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", now.plusSeconds(120)),
                SessionDeadlines.createdAt(now));
    }

    private Digest32 digest(int marker) {
        byte[] bytes = new byte[32];
        bytes[0] = (byte) marker;
        return Digest32.fromBytes(bytes);
    }
}
