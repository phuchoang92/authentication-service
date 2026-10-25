package com.vpbank.dcp.auth.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * {@link CaptchaStore} on Valkey: one HASH per challenge {@code {customerId, answerDigest, expiresAtMs}}
 * with TTL at the expiry. {@code consume} is WATCH → read → MULTI DEL → EXEC, so a challenge can be
 * used once even under concurrent attempts; the comparison happens after the delete succeeded.
 */
@RequiredArgsConstructor
public final class ValkeyCaptchaStore implements CaptchaStore {
    static final String F_CUSTOMER = "customerId";
    static final String F_DIGEST = "answerDigest";
    static final String F_EXPIRES = "expiresAtMs";
    /** Unknown user names get a challenge bound to nobody. */
    static final String NOBODY = "";

    @NonNull private final StringRedisTemplate redis;
    @NonNull private final CaptchaKeys keys;
    @NonNull private final Clock clock;

    @Override
    public void save(CaptchaId id, CustomerId customerId, CaptchaAnswer answer, Instant expiresAt) {
        String key = keys.forChallenge(id);
        Map<String, String> fields = Map.of(
                F_CUSTOMER, customerId == null ? NOBODY : customerId.value(),
                F_DIGEST, keys.answerDigest(answer),
                F_EXPIRES, Long.toString(expiresAt.toEpochMilli()));
        try {
            redis.execute(new SessionCallback<List<Object>>() {
                @Override
                @SuppressWarnings("unchecked")
                public <K, V> List<Object> execute(RedisOperations<K, V> operations) {
                    var ops = (RedisOperations<String, String>) operations;
                    ops.multi();
                    ops.opsForHash().putAll(key, fields);
                    ops.expireAt(key, expiresAt);
                    return ops.exec();
                }
            });
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    @Override
    public boolean consume(CaptchaId id, CustomerId customerId, CaptchaAnswer answer) {
        String key = keys.forChallenge(id);
        try {
            Map<Object, Object> taken = redis.execute(new SessionCallback<Map<Object, Object>>() {
                @Override
                @SuppressWarnings("unchecked")
                public <K, V> Map<Object, Object> execute(RedisOperations<K, V> operations) {
                    var ops = (RedisOperations<String, String>) operations;
                    ops.watch(key);
                    Map<Object, Object> fields = ops.opsForHash().entries(key);
                    if (fields == null || fields.isEmpty()) {
                        ops.unwatch();
                        return null;
                    }
                    ops.multi();
                    ops.delete(key);
                    List<Object> result = ops.exec();
                    return result == null || result.isEmpty() ? null : fields; // null: someone else consumed it first
                }
            });
            return taken != null && matches(taken, customerId, answer);
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    private boolean matches(Map<Object, Object> fields, CustomerId customerId, CaptchaAnswer answer) {
        String owner = String.valueOf(fields.get(F_CUSTOMER));
        String expires = String.valueOf(fields.get(F_EXPIRES));
        String digest = String.valueOf(fields.get(F_DIGEST));
        boolean live;
        try {
            live = clock.instant().toEpochMilli() < Long.parseLong(expires);
        } catch (NumberFormatException malformed) {
            return false;
        }
        boolean sameOwner = customerId != null && customerId.value().equals(owner);
        return live && sameOwner && MessageDigest.isEqual(digest.getBytes(StandardCharsets.UTF_8),
                keys.answerDigest(answer).getBytes(StandardCharsets.UTF_8));
    }
}
