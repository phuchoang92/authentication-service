package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
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
 * {@link SessionStore} on Valkey with native commands (no Lua; integration-grade per contract 16).
 * One HASH per session under the token's keyed lookup; {@code PEXPIREAT} mirrors the idle deadline.
 * Writes are compare-and-set: {@code WATCH} the key, read, compare {@code sessionVersion}, then
 * {@code MULTI … EXEC}; an aborted {@code EXEC} means another client moved the key first (stale).
 * Spring exceptions never leave this class.
 */
@RequiredArgsConstructor
public final class ValkeySessionAdapter implements SessionStore {
    @NonNull private final StringRedisTemplate stringRedisTemplate;
    @NonNull private final SessionKeys sessionKeys;

    @Override
    public void create(Session session, OpaqueToken token) {
        SessionLookup sessionLookup = sessionKeys.lookupOf(token);
        String key = sessionKeys.forLookup(sessionLookup);
        Map<String, String> fields = SessionHashCodec.encode(session);
        translate(() -> stringRedisTemplate.execute(new SessionCallback<List<Object>>() {
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
        SessionLookup sessionLookup = sessionKeys.lookupOf(token);
        return findByLookup(sessionLookup);
    }

    @Override
    public Optional<StoredSession> findByLookup(SessionLookup lookup) {
        String key = sessionKeys.forLookup(lookup);
        return translate(() -> read(key).map(session -> new StoredSession(lookup, session)));
    }

    @Override
    public Optional<Session> saveIfCurrent(SessionLookup lookup, Session changed) {
        String key = sessionKeys.forLookup(lookup);
        long expectedVersion = changed.sessionVersion();
        Session nextVersion = changed.withSessionVersion(expectedVersion + 1);
        Map<String, String> fields = SessionHashCodec.encode(nextVersion);

        boolean written = translate(() -> compareAndSet(key, expectedVersion, ops -> {
            ops.opsForHash().putAll(key, fields);
            ops.expireAt(key, nextVersion.idleExpiresAt());
        }));
        if (!written) {
            return Optional.empty();
        }
        return Optional.of(nextVersion);
    }

    @Override
    public boolean deleteIfCurrent(SessionLookup lookup, Session current) {
        String key = sessionKeys.forLookup(lookup);
        return translate(() -> compareAndSet(key, current.sessionVersion(), ops -> ops.delete(key)));
    }

    /** WATCH key → stored version must equal {@code expectedVersion} → MULTI, write, EXEC. */
    private boolean compareAndSet(String key, long expectedVersion, Consumer<RedisOperations<String, String>> write) {
        List<Object> execResult = stringRedisTemplate.execute(new SessionCallback<List<Object>>() {
            @Override
            @SuppressWarnings("unchecked")
            public <K, V> List<Object> execute(RedisOperations<K, V> operations) {
                var ops = (RedisOperations<String, String>) operations;
                ops.watch(key);
                Optional<Session> storedSession = read(ops, key);
                boolean isExpectedVersion = storedSession.isPresent()
                        && storedSession.get().sessionVersion() == expectedVersion;
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

    private Optional<Session> read(String key) {
        return read(stringRedisTemplate, key);
    }

    private static Optional<Session> read(RedisOperations<String, String> ops, String key) {
        Map<Object, Object> rawFields = ops.opsForHash().entries(key);
        if (rawFields == null || rawFields.isEmpty()) {
            return Optional.empty();
        }
        Map<String, String> fields = rawFields.entrySet().stream()
                .collect(Collectors.toMap(
                        field -> String.valueOf(field.getKey()),
                        field -> String.valueOf(field.getValue())));
        return SessionHashCodec.decode(fields);
    }

    private static <T> T translate(Supplier<T> storeCall) {
        try {
            return storeCall.get();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
