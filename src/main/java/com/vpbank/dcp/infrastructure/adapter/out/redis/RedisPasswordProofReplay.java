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
            if (!reserveKey(dpopKeys.forDpop(attempt.requestKey(), attempt.proofIds().dpop()))
                    || !reserveKey(passwordKeys.forRequestKey(
                            attempt.requestKey(), attempt.proofIds().requestKey()))) {
                return new PasswordReplayResult.Replayed();
            }
            if (attempt.deviceKeyThumbprint() != null
                    && !reserveKey(passwordKeys.forDeviceKey(
                            attempt.deviceKeyThumbprint(), attempt.proofIds().deviceKey()))) {
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

    private boolean reserveKey(String key) {
        Boolean reserved = redis.opsForValue().setIfAbsent(key, "1", REPLAY_TTL);
        if (reserved == null) {
            throw new InvalidAuthorityRedisConfigurationException();
        }
        return reserved;
    }
}
