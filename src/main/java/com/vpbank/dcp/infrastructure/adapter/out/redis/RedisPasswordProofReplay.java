package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.port.out.password.PasswordProofReplay;
import com.vpbank.dcp.core.port.out.password.PasswordReplayAttempt;
import com.vpbank.dcp.core.port.out.password.PasswordReplayResult;
import com.vpbank.dcp.core.port.out.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.PasswordProofReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ReplayKeys;
import java.time.Duration;
import java.util.Objects;
import java.util.UUID;
import org.springframework.data.redis.core.StringRedisTemplate;

/** Proof markers are never rolled back: a partial reservation can only deny a retry. */
public final class RedisPasswordProofReplay implements PasswordProofReplay {

    private static final Duration REPLAY_TTL = Duration.ofSeconds(120);
    private static final Duration OPERATION_TTL = Duration.ofMinutes(15);

    private final StringRedisTemplate redis;
    private final RedisServerIdentity identity;
    private final ReplayKeys dpopKeys;
    private final PasswordProofReplayKeys passwordKeys;

    public RedisPasswordProofReplay(StringRedisTemplate redis, RedisServerIdentity identity,
                                    ReplayKeys dpopKeys, PasswordProofReplayKeys passwordKeys) {
        this.redis = Objects.requireNonNull(redis);
        this.identity = Objects.requireNonNull(identity);
        this.dpopKeys = Objects.requireNonNull(dpopKeys);
        this.passwordKeys = Objects.requireNonNull(passwordKeys);
    }

    @Override
    public PasswordReplayResult reserve(PasswordReplayAttempt attempt) {
        Objects.requireNonNull(attempt);
        try {
            UUID generation = identity.currentGeneration().orElse(null);
            if (generation == null) {
                return new PasswordReplayResult.AuthorityClosed();
            }
            if (!reserveKey(passwordKeys.forOperation(attempt.operationId()), OPERATION_TTL)
                    || !reserveKey(dpopKeys.forDpop(attempt.requestKey(), attempt.proofIds().dpop()), REPLAY_TTL)
                    || !reserveKey(passwordKeys.forRequestKey(
                            attempt.requestKey(), attempt.proofIds().requestKey()), REPLAY_TTL)) {
                return new PasswordReplayResult.Replayed();
            }
            if (attempt.deviceKeyThumbprint() != null
                    && !reserveKey(passwordKeys.forDeviceKey(
                            attempt.deviceKeyThumbprint(), attempt.proofIds().deviceKey()), REPLAY_TTL)) {
                return new PasswordReplayResult.Replayed();
            }
            if (!generation.equals(identity.currentGeneration().orElse(null))) {
                return new PasswordReplayResult.AuthorityClosed();
            }
            return new PasswordReplayResult.Reserved(generation);
        } catch (RuntimeException failure) {
            throw new ReplayAuthorityUnavailableException(failure);
        }
    }

    private boolean reserveKey(String key, Duration ttl) {
        Boolean reserved = redis.opsForValue().setIfAbsent(key, "1", ttl);
        if (reserved == null) {
            throw new InvalidAuthorityRedisConfigurationException();
        }
        return reserved;
    }
}
