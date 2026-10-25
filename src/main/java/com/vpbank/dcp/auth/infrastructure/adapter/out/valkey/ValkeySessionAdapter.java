package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * {@link SessionStore} on Valkey with native commands (no Lua; integration-grade per contract 16).
 * One HASH per session under the token's keyed lookup; {@code PEXPIREAT} mirrors the idle deadline.
 * Writes are compare-and-set: {@code WATCH} the key, read, compare {@code sessionVersion}, then
 * {@code MULTI … EXEC}; an aborted {@code EXEC} means another client moved the key first (stale).
 * Spring exceptions never leave this class.
 */
@RequiredArgsConstructor
public final class ValkeySessionAdapter implements SessionStore {
    @NonNull private final StringRedisTemplate redis;
    @NonNull private final SessionKeys keys;

    @Override
    public void create(Session session, OpaqueToken token) {
        String key = keys.forLookup(keys.lookupOf(token));
        Map<String, String> fields = SessionHashCodec.encode(session);
        translate(() -> redis.execute(new SessionCallback<List<Object>>() {
            @Override
            @SuppressWarnings("unchecked")
            public <K, V> List<Object> execute(RedisOperations<K, V> operations) {
                var ops = (RedisOperations<String, String>) operations;
                ops.multi();
                ops.opsForHash().putAll(key, fields);
                ops.expireAt(key, session.idleExpiresAt());
                return ops.exec();
            }
        }));
    }

    @Override
    public Optional<StoredSession> findByToken(OpaqueToken token) {
        return findByLookup(keys.lookupOf(token));
    }

    @Override
    public Optional<StoredSession> findByLookup(SessionLookup lookup) {
        return translate(() -> read(keys.forLookup(lookup)).map(session -> new StoredSession(lookup, session)));
    }

    @Override
    public Optional<Session> saveIfCurrent(SessionLookup lookup, Session changed) {
        String key = keys.forLookup(lookup);
        Session saved = changed.withSessionVersion(changed.sessionVersion() + 1);
        return translate(() -> compareAndSet(key, changed.sessionVersion(), ops -> {
            ops.opsForHash().putAll(key, SessionHashCodec.encode(saved));
            ops.expireAt(key, saved.idleExpiresAt());
        }) ? Optional.of(saved) : Optional.empty());
    }

    @Override
    public boolean deleteIfCurrent(SessionLookup lookup, Session current) {
        String key = keys.forLookup(lookup);
        return translate(() -> compareAndSet(key, current.sessionVersion(), ops -> ops.delete(key)));
    }

    /** WATCH key → stored version must equal {@code expectedVersion} → MULTI, write, EXEC. */
    private boolean compareAndSet(String key, long expectedVersion, Consumer<RedisOperations<String, String>> write) {
        List<Object> result = redis.execute(new SessionCallback<List<Object>>() {
            @Override
            @SuppressWarnings("unchecked")
            public <K, V> List<Object> execute(RedisOperations<K, V> operations) {
                var ops = (RedisOperations<String, String>) operations;
                ops.watch(key);
                Optional<Session> stored = read(ops, key);
                if (stored.isEmpty() || stored.get().sessionVersion() != expectedVersion) {
                    ops.unwatch();
                    return null;
                }
                ops.multi();
                write.accept(ops);
                return ops.exec(); // null when WATCH saw a concurrent change
            }
        });
        return result != null && !result.isEmpty();
    }

    private Optional<Session> read(String key) {
        return read(redis, key);
    }

    private static Optional<Session> read(RedisOperations<String, String> ops, String key) {
        Map<Object, Object> raw = ops.opsForHash().entries(key);
        if (raw == null || raw.isEmpty()) {
            return Optional.empty();
        }
        Map<String, String> fields = raw.entrySet().stream()
                .collect(Collectors.toMap(e -> String.valueOf(e.getKey()), e -> String.valueOf(e.getValue())));
        return SessionHashCodec.decode(fields);
    }

    private static <T> T translate(Supplier<T> call) {
        try {
            return call.get();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
