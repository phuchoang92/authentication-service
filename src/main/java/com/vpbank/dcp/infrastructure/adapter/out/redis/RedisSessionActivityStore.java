package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.session.SessionDeadlines;
import com.vpbank.dcp.core.session.LiveSession;
import com.vpbank.dcp.core.session.SessionActivityStore;
import com.vpbank.dcp.core.session.SessionActivityUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Reads ACTIVE session hashes written by {@link RedisSessionAuthority} and slides their idle
 * deadline with plain commands: {@code WATCH} → check {@code sessionVersion} → {@code MULTI}
 * → {@code EXEC}. A concurrent slide or a revoke {@code DEL} makes {@code EXEC} abort, so a
 * deleted session is never written again.
 *
 * <p>Integration-only, like {@link RedisSessionAuthority}.
 */
public final class RedisSessionActivityStore implements SessionActivityStore {
    /** Exactly the fields {@link RedisSessionAuthority} writes; anything else is not ACTIVE. */
    static final Set<String> ACTIVE_FIELDS = Set.of("schemaVersion", "state", "sessionId", "secretDigest",
            "subjectId", "appId", "audience", "channel", "scope", "deviceBindingId", "requestKeyJkt",
            "requestPublicJwk", "generation", "customerSecurityVersion", "credentialSecurityVersion",
            "deviceSecurityVersion", "sessionVersion", "customerStatusVersion",
            "customerStatusValidUntilMs", "createdAtMs", "idleExpiresAtMs", "absoluteExpiresAtMs",
            "nonceFamilyId", "assurance");

    private final StringRedisTemplate redis;
    private final RedisServerIdentity identity;
    private final SessionKeys sessions = new SessionKeys();

    public RedisSessionActivityStore(StringRedisTemplate redis, RedisServerIdentity identity) {
        this.redis = Objects.requireNonNull(redis);
        this.identity = Objects.requireNonNull(identity);
    }

    @Override
    public Optional<UUID> currentGeneration() {
        try {
            return identity.currentGeneration();
        } catch (RuntimeException failure) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<LiveSession> find(UUID sessionId) {
        Objects.requireNonNull(sessionId);
        String key = sessions.forSession(sessionId);
        Map<Object, Object> raw;
        Long ttl;
        try {
            raw = redis.opsForHash().entries(key);
            ttl = redis.getExpire(key, TimeUnit.MILLISECONDS);
        } catch (RuntimeException failure) {
            throw new SessionActivityUnavailableException(failure);
        }
        if (ttl == null || ttl <= 0) {
            return Optional.empty();
        }
        try {
            return decode(raw);
        } catch (RuntimeException corrupt) {
            // Anything that is not exactly this codec denies; it never degrades to a default.
            return Optional.empty();
        }
    }

    @Override
    public boolean slideIdle(UUID sessionId, long expectedVersion, Instant idleExpiresAt) {
        Objects.requireNonNull(sessionId);
        Objects.requireNonNull(idleExpiresAt);
        String key = sessions.forSession(sessionId);
        try {
            return Boolean.TRUE.equals(redis.execute(new SessionCallback<Boolean>() {
                @Override
                @SuppressWarnings("unchecked")
                public Boolean execute(RedisOperations operations) throws DataAccessException {
                    RedisOperations<String, String> ops = operations;
                    ops.watch(key);
                    Object stored = ops.opsForHash().get(key, "sessionVersion");
                    if (!Long.toString(expectedVersion).equals(stored)) {
                        ops.unwatch();
                        return false;
                    }
                    ops.multi();
                    ops.opsForHash().put(key, "idleExpiresAtMs",
                            Long.toString(idleExpiresAt.toEpochMilli()));
                    ops.opsForHash().increment(key, "sessionVersion", 1);
                    ops.expireAt(key, Date.from(idleExpiresAt));
                    List<Object> applied = ops.exec();
                    return applied != null && !applied.isEmpty();
                }
            }));
        } catch (RuntimeException failure) {
            // EXEC may or may not have run: the caller must not report success.
            throw new SessionActivityUnavailableException(failure);
        }
    }

    private Optional<LiveSession> decode(Map<Object, Object> raw) {
        Map<String, String> f = new HashMap<>();
        raw.forEach((name, value) -> f.put((String) name, (String) value));
        if (!ACTIVE_FIELDS.equals(f.keySet()) || !"1".equals(f.get("schemaVersion"))
                || !"ACTIVE".equals(f.get("state"))) {
            return Optional.empty();
        }
        SessionDeadlines deadlines = new SessionDeadlines(millis(f, "idleExpiresAtMs"),
                millis(f, "absoluteExpiresAtMs"));
        return Optional.of(new LiveSession(
                new RequestKeyThumbprint(Digest32.fromBase64Url(f.get("requestKeyJkt"))),
                UUID.fromString(f.get("generation")), deadlines,
                millis(f, "customerStatusValidUntilMs"), Long.parseLong(f.get("sessionVersion"))));
    }

    private static Instant millis(Map<String, String> fields, String name) {
        return Instant.ofEpochMilli(Long.parseLong(fields.get(name)));
    }
}
