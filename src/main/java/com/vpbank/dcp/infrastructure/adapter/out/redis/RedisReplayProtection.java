package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.replay.ReplayAttempt;
import com.vpbank.dcp.core.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.core.replay.ReplayProtection;
import com.vpbank.dcp.core.replay.ReplayReservation;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ReplayKeys;
import java.time.Duration;
import java.util.Objects;
import java.util.UUID;
import org.springframework.data.redis.core.StringRedisTemplate;

/** Single-key replay protection for the integration-only password slice. */
public final class RedisReplayProtection implements ReplayProtection {

    private static final Duration REPLAY_TTL = Duration.ofSeconds(120);

    private final StringRedisTemplate redis;
    private final RedisServerIdentity identity;
    private final ReplayKeys keys;

    public RedisReplayProtection(StringRedisTemplate redis, RedisServerIdentity identity,
                                 ReplayKeys keys) {
        this.redis = Objects.requireNonNull(redis);
        this.identity = Objects.requireNonNull(identity);
        this.keys = Objects.requireNonNull(keys);
    }

    @Override
    public ReplayReservation reserve(ReplayAttempt attempt) {
        Objects.requireNonNull(attempt);
        try {
            UUID generation = identity.currentGeneration().orElse(null);
            if (generation == null || !generation.equals(attempt.generation())) {
                return ReplayReservation.AUTHORITY_CLOSED;
            }
            Boolean reserved = redis.opsForValue().setIfAbsent(
                    keys.forDpop(attempt.requestKey(), attempt.proofIdDigest()), "1", REPLAY_TTL);
            if (reserved == null) {
                return ReplayReservation.AUTHORITY_CLOSED;
            }
            if (!generation.equals(identity.currentGeneration().orElse(null))) {
                return ReplayReservation.AUTHORITY_CLOSED;
            }
            return reserved ? ReplayReservation.RESERVED : ReplayReservation.REPLAYED;
        } catch (RuntimeException failure) {
            throw new ReplayAuthorityUnavailableException(failure);
        }
    }
}
