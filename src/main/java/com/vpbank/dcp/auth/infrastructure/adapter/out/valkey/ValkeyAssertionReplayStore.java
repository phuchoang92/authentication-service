package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Used BFF assertion IDs on Valkey: one {@code SET NX} per admitted request, expiring when the assertion
 * could no longer pass the expiry check. Of two requests carrying the same ID exactly one is first. A store
 * that does not answer is unavailable, never "first use".
 */
@RequiredArgsConstructor
public final class ValkeyAssertionReplayStore {
    static final String USED = "1";
    /** Valkey refuses a zero expiry; an ID already at its deadline is still remembered briefly. */
    private static final Duration SHORTEST_MEMORY = Duration.ofMillis(1);

    @NonNull private final StringRedisTemplate stringRedisTemplate;
    @NonNull private final BffAssertionKeys bffAssertionKeys;
    @NonNull private final Clock clock;

    public boolean firstUse(String assertionId, Instant rememberUntil) {
        String key = bffAssertionKeys.forAssertionId(assertionId);
        Duration memory = Duration.between(clock.instant(), rememberUntil);
        if (memory.compareTo(SHORTEST_MEMORY) < 0) {
            memory = SHORTEST_MEMORY;
        }
        try {
            Boolean stored = stringRedisTemplate.opsForValue().setIfAbsent(key, USED, memory);
            if (stored == null) {
                throw new RepositoryUnavailableException(new IllegalStateException("SET NX gave no answer"));
            }
            return stored;
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
