package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentTransactionStore;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * {@link EnrollmentTransactionStore} on Valkey with native commands (no Lua, contract 16). One HASH per device
 * under {@link EnrollmentTransactionKeys}; {@code PEXPIREAT} mirrors {@code expiresAt}. Every write is
 * {@code WATCH} → read → compare → {@code MULTI … EXEC}; an aborted {@code EXEC} means another client moved the
 * key first. A save replaces the whole HASH ({@code DEL} then {@code HSET}) so a field the new value no longer
 * has cannot linger. Spring exceptions never leave this class.
 */
@RequiredArgsConstructor
public final class ValkeyEnrollmentTransactionAdapter implements EnrollmentTransactionStore {
    @NonNull private final StringRedisTemplate stringRedisTemplate;
    @NonNull private final EnrollmentTransactionKeys enrollmentTransactionKeys;

    @Override
    public boolean createIfAbsent(EnrollmentTransaction fresh) {
        if (fresh.version() != 0) {
            throw new IllegalArgumentException("A new enrollment transaction starts at version 0");
        }
        String key = keyOf(fresh);
        Map<String, String> fields = EnrollmentTransactionHashCodec.encode(fresh);

        return translate(() -> {
            List<Object> execResult = stringRedisTemplate.execute(new SessionCallback<List<Object>>() {
                @Override
                @SuppressWarnings("unchecked")
                public <K, V> List<Object> execute(RedisOperations<K, V> operations) {
                    var ops = (RedisOperations<String, String>) operations;
                    ops.watch(key);
                    boolean deviceHasOne = Boolean.TRUE.equals(ops.hasKey(key));
                    if (deviceHasOne) {
                        ops.unwatch();
                        return null;
                    }
                    ops.multi();
                    ops.opsForHash().putAll(key, fields);
                    ops.expireAt(key, fresh.expiresAt());
                    return ops.exec(); // null when another init took the key in between
                }
            });
            return execResult != null && !execResult.isEmpty();
        });
    }

    @Override
    public Optional<EnrollmentTransaction> find(CustomerId customerId, Channel channel, DeviceId deviceId) {
        String key = enrollmentTransactionKeys.forDevice(customerId, channel, deviceId);
        return translate(() -> read(stringRedisTemplate, key))
                .filter(transaction -> transaction.customerId().equals(customerId))
                .filter(transaction -> transaction.channel() == channel)
                .filter(transaction -> transaction.deviceId().equals(deviceId));
    }

    @Override
    public Optional<EnrollmentTransaction> saveIfCurrent(EnrollmentTransaction changed) {
        String key = keyOf(changed);
        long expectedVersion = changed.version();
        EnrollmentTransaction nextVersion = changed.withVersion(expectedVersion + 1);
        Map<String, String> fields = EnrollmentTransactionHashCodec.encode(nextVersion);

        boolean written = translate(() -> compareAndSet(key, expectedVersion, ops -> {
            ops.opsForHash().putAll(key, fields);
            ops.expireAt(key, nextVersion.expiresAt());
        }));
        if (!written) {
            return Optional.empty();
        }
        return Optional.of(nextVersion);
    }

    @Override
    public boolean deleteIfCurrent(EnrollmentTransaction current) {
        String key = keyOf(current);
        return translate(() -> compareAndSet(key, current.version(), ops -> ops.delete(key)));
    }

    private String keyOf(EnrollmentTransaction transaction) {
        return enrollmentTransactionKeys.forDevice(transaction.customerId(), transaction.channel(), transaction.deviceId());
    }

    /** WATCH key → stored version must equal {@code expectedVersion} → MULTI, write, EXEC. */
    private boolean compareAndSet(String key, long expectedVersion, Consumer<RedisOperations<String, String>> write) {
        List<Object> execResult = stringRedisTemplate.execute(new SessionCallback<List<Object>>() {
            @Override
            @SuppressWarnings("unchecked")
            public <K, V> List<Object> execute(RedisOperations<K, V> operations) {
                var ops = (RedisOperations<String, String>) operations;
                ops.watch(key);
                Optional<EnrollmentTransaction> storedTransaction = read(ops, key);
                boolean isExpectedVersion = storedTransaction.isPresent()
                        && storedTransaction.get().version() == expectedVersion;
                if (!isExpectedVersion) {
                    ops.unwatch();
                    return null;
                }
                ops.multi();
                write.accept(ops);
                return ops.exec(); // null when WATCH saw a concurrent change
            }
        });
        return execResult != null && !execResult.isEmpty();
    }

    private static Optional<EnrollmentTransaction> read(RedisOperations<String, String> ops, String key) {
        Map<Object, Object> rawFields = ops.opsForHash().entries(key);
        if (rawFields == null || rawFields.isEmpty()) {
            return Optional.empty();
        }
        Map<String, String> fields = rawFields.entrySet().stream()
                .collect(Collectors.toMap(
                        field -> String.valueOf(field.getKey()),
                        field -> String.valueOf(field.getValue())));
        return EnrollmentTransactionHashCodec.decode(fields);
    }

    private static <T> T translate(Supplier<T> storeCall) {
        try {
            return storeCall.get();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
