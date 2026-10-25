package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

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

    @NonNull private final StringRedisTemplate stringRedisTemplate;
    @NonNull private final CaptchaKeys captchaKeys;
    @NonNull private final Clock clock;

    @Override
    public void save(CaptchaId id, CustomerId customerId, CaptchaAnswer answer, Instant expiresAt) {
        String key = captchaKeys.forChallenge(id);
        String boundCustomer = customerId == null ? NOBODY : customerId.value();
        Map<String, String> fields = Map.of(
                F_CUSTOMER, boundCustomer,
                F_DIGEST, captchaKeys.answerDigest(answer),
                F_EXPIRES, Long.toString(expiresAt.toEpochMilli()));
        try {
            stringRedisTemplate.execute(new SessionCallback<List<Object>>() {
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
        String key = captchaKeys.forChallenge(id);
        try {
            Map<Object, Object> consumedFields = stringRedisTemplate.execute(new SessionCallback<Map<Object, Object>>() {
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
                    List<Object> execResult = ops.exec();
                    boolean deletedByThisCall = execResult != null && !execResult.isEmpty();
                    if (!deletedByThisCall) {
                        return null; // someone else consumed it first
                    }
                    return fields;
                }
            });
            if (consumedFields == null) {
                return false;
            }
            return matches(consumedFields, customerId, answer);
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    private boolean matches(Map<Object, Object> fields, CustomerId customerId, CaptchaAnswer answer) {
        String boundCustomer = String.valueOf(fields.get(F_CUSTOMER));
        String expiresAtMillis = String.valueOf(fields.get(F_EXPIRES));
        String storedAnswerDigest = String.valueOf(fields.get(F_DIGEST));

        boolean live;
        try {
            live = clock.instant().toEpochMilli() < Long.parseLong(expiresAtMillis);
        } catch (NumberFormatException malformed) {
            return false;
        }

        boolean sameOwner = customerId != null && customerId.value().equals(boundCustomer);

        byte[] storedDigest = storedAnswerDigest.getBytes(StandardCharsets.UTF_8);
        byte[] givenDigest = captchaKeys.answerDigest(answer).getBytes(StandardCharsets.UTF_8);
        boolean sameAnswer = MessageDigest.isEqual(storedDigest, givenDigest);

        return live && sameOwner && sameAnswer;
    }
}
