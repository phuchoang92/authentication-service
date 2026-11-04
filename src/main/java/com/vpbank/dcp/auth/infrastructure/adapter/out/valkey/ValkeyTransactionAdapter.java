package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import com.vpbank.dcp.auth.application.port.out.repository.TransactionStore;
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
 * {@link TransactionStore} on Valkey with native commands (no Lua, contract 16). One HASH per transaction under
 * {@link TransactionKeys}; {@code PEXPIREAT} mirrors {@code expiresAt}. Every write is {@code WATCH} → read →
 * compare version → {@code MULTI … EXEC}; an aborted {@code EXEC} means another client moved the key first. A
 * save replaces the whole HASH ({@code DEL} then {@code HSET}) so nothing stale lingers. Spring exceptions never
 * leave this class. This is the one place the compare-and-set is written; flows see only the port.
 */
@RequiredArgsConstructor
public final class ValkeyTransactionAdapter implements TransactionStore {
    @NonNull private final StringRedisTemplate stringRedisTemplate;
    @NonNull private final TransactionKeys transactionKeys;
    @NonNull private final TransactionHashCodec transactionHashCodec;

    @Override
    public <P> boolean createIfAbsent(CacheTransaction<P> fresh) {
        if (fresh.version() != 0) {
            throw new IllegalArgumentException("A new transaction starts at version 0");
        }
        String key = transactionKeys.forTransaction(fresh);
        Map<String, String> fields = transactionHashCodec.encode(fresh);

        return translate(() -> {
            List<Object> execResult = stringRedisTemplate.execute(new SessionCallback<List<Object>>() {
                @Override
                @SuppressWarnings("unchecked")
                public <K, V> List<Object> execute(RedisOperations<K, V> operations) {
                    var ops = (RedisOperations<String, String>) operations;
                    ops.watch(key);
                    boolean alreadyThere = Boolean.TRUE.equals(ops.hasKey(key));
                    if (alreadyThere) {
                        ops.unwatch();
                        return null;
                    }
                    ops.multi();
                    ops.opsForHash().putAll(key, fields);
                    ops.expireAt(key, fresh.expiresAt());
                    return ops.exec(); // null when another create took the key in between
                }
            });
            return execResult != null && !execResult.isEmpty();
        });
    }

    @Override
    public <P> Optional<CacheTransaction<P>> find(TransactionKind<P> kind, String id) {
        String key = transactionKeys.forTransaction(kind, id);
        return translate(() -> read(stringRedisTemplate, key, kind, id));
    }

    @Override
    public <P> Optional<CacheTransaction<P>> saveIfCurrent(CacheTransaction<P> changed) {
        String key = transactionKeys.forTransaction(changed);
        long expectedVersion = changed.version();
        CacheTransaction<P> nextVersion = changed.withVersion(expectedVersion + 1);
        Map<String, String> fields = transactionHashCodec.encode(nextVersion);

        boolean written = translate(() -> compareAndSet(key, changed, ops -> {
            ops.delete(key);
            ops.opsForHash().putAll(key, fields);
            ops.expireAt(key, nextVersion.expiresAt());
        }));
        if (!written) {
            return Optional.empty();
        }
        return Optional.of(nextVersion);
    }

    @Override
    public <P> boolean deleteIfCurrent(CacheTransaction<P> current) {
        String key = transactionKeys.forTransaction(current);
        return translate(() -> compareAndSet(key, current, ops -> ops.delete(key)));
    }

    /** WATCH key → the stored transaction must have {@code expected.version()} → MULTI, write, EXEC. */
    private <P> boolean compareAndSet(String key, CacheTransaction<P> expected,
                                      Consumer<RedisOperations<String, String>> write) {
        List<Object> execResult = stringRedisTemplate.execute(new SessionCallback<List<Object>>() {
            @Override
            @SuppressWarnings("unchecked")
            public <K, V> List<Object> execute(RedisOperations<K, V> operations) {
                var ops = (RedisOperations<String, String>) operations;
                ops.watch(key);
                Optional<CacheTransaction<P>> stored = read(ops, key, expected.kind(), expected.id());
                boolean isExpectedVersion = stored.isPresent() && stored.get().version() == expected.version();
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

    private <P> Optional<CacheTransaction<P>> read(RedisOperations<String, String> ops, String key,
                                                   TransactionKind<P> kind, String id) {
        Map<Object, Object> rawFields = ops.opsForHash().entries(key);
        if (rawFields == null || rawFields.isEmpty()) {
            return Optional.empty();
        }
        Map<String, String> fields = rawFields.entrySet().stream()
                .collect(Collectors.toMap(
                        field -> String.valueOf(field.getKey()),
                        field -> String.valueOf(field.getValue())));
        return transactionHashCodec.decode(kind, id, fields);
    }

    private static <T> T translate(Supplier<T> storeCall) {
        try {
            return storeCall.get();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
