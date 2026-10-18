package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.replay.AssertionReplay;
import com.vpbank.dcp.core.port.out.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.core.port.out.replay.ReplayReservation;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ReplayKeys;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import org.springframework.data.redis.core.StringRedisTemplate;

/** Keeps each BFF assertion marker until the assertion itself can no longer be accepted. */
public final class RedisAssertionReplay implements AssertionReplay {
    /** Covers the clock skew the verifier tolerates around {@code iat}/{@code exp}. */
    private static final Duration SKEW = Duration.ofSeconds(5);

    private final StringRedisTemplate redis;
    private final ReplayKeys keys;
    private final Clock clock;

    public RedisAssertionReplay(StringRedisTemplate redis, ReplayKeys keys, Clock clock) {
        this.redis = Objects.requireNonNull(redis);
        this.keys = Objects.requireNonNull(keys);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public ReplayReservation reserve(Digest32 assertionIdDigest, Instant assertionExpiresAt) {
        Objects.requireNonNull(assertionIdDigest);
        Objects.requireNonNull(assertionExpiresAt);
        Duration ttl = Duration.between(clock.instant(), assertionExpiresAt).plus(SKEW);
        if (ttl.compareTo(SKEW) <= 0) {
            return ReplayReservation.REPLAYED;
        }
        try {
            Boolean reserved = redis.opsForValue().setIfAbsent(
                    keys.forBffAssertion(assertionIdDigest), "1", ttl);
            if (reserved == null) {
                return ReplayReservation.AUTHORITY_CLOSED;
            }
            return reserved ? ReplayReservation.RESERVED : ReplayReservation.REPLAYED;
        } catch (RuntimeException failure) {
            throw new ReplayAuthorityUnavailableException(failure);
        }
    }
}
