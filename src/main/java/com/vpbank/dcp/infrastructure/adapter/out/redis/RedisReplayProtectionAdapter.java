package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.port.out.replay.ReplayAttempt;
import com.vpbank.dcp.core.port.out.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.core.port.out.replay.ReplayProtection;
import com.vpbank.dcp.core.port.out.replay.ReplayReservation;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GenerationKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ReplayKeys;
import java.util.List;
import java.util.Objects;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

public final class RedisReplayProtectionAdapter implements ReplayProtection {

    private final StringRedisTemplate redis;
    private final RedisServerIdentity identity;
    private final ReplayKeys replayKeys;
    private final GenerationKeys generationKeys;
    private final DefaultRedisScript<String> reserveScript;

    public RedisReplayProtectionAdapter(
            StringRedisTemplate redis,
            ReplayKeys replayKeys,
            GenerationKeys generationKeys,
            DefaultRedisScript<String> reserveScript) {
        this.redis = Objects.requireNonNull(redis, "redis");
        this.identity = new RedisServerIdentity(redis);
        this.replayKeys = Objects.requireNonNull(replayKeys, "replayKeys");
        this.generationKeys = Objects.requireNonNull(generationKeys, "generationKeys");
        this.reserveScript = Objects.requireNonNull(reserveScript, "reserveScript");
    }

    @Override
    public ReplayReservation reserve(ReplayAttempt attempt) {
        Objects.requireNonNull(attempt, "attempt");
        String controlKey = generationKeys.control();
        String replayKey = replayKeys.forDpop(attempt.requestKey(), attempt.proofIdDigest());

        try {
            String observedRunId = identity.currentRunId();
            if (observedRunId == null || observedRunId.isBlank()) {
                return ReplayReservation.AUTHORITY_CLOSED;
            }

            String result = redis.execute(
                    reserveScript,
                    List.of(controlKey, replayKey),
                    attempt.generation().toString(),
                    observedRunId);
            return switch (result) {
                case "RESERVED" -> ReplayReservation.RESERVED;
                case "REPLAYED" -> ReplayReservation.REPLAYED;
                case "AUTHORITY_CLOSED" -> ReplayReservation.AUTHORITY_CLOSED;
                case null, default -> ReplayReservation.AUTHORITY_CLOSED;
            };
        } catch (RuntimeException failure) {
            throw new ReplayAuthorityUnavailableException(failure);
        }
    }
}
