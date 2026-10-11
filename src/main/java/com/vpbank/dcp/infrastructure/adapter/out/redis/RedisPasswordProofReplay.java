package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.port.out.password.PasswordProofReplay;
import com.vpbank.dcp.core.port.out.password.PasswordReplayAttempt;
import com.vpbank.dcp.core.port.out.password.PasswordReplayResult;
import com.vpbank.dcp.core.port.out.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GenerationKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.PasswordProofReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ReplayKeys;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

public final class RedisPasswordProofReplay implements PasswordProofReplay {

    private final StringRedisTemplate redis;
    private final RedisServerIdentity identity;
    private final GenerationKeys generationKeys;
    private final ReplayKeys dpopKeys;
    private final PasswordProofReplayKeys passwordKeys;
    private final DefaultRedisScript<String> script;

    public RedisPasswordProofReplay(StringRedisTemplate redis, GenerationKeys generationKeys,
                                    ReplayKeys dpopKeys, PasswordProofReplayKeys passwordKeys,
                                    DefaultRedisScript<String> script) {
        this.redis = Objects.requireNonNull(redis, "redis");
        this.identity = new RedisServerIdentity(redis);
        this.generationKeys = Objects.requireNonNull(generationKeys, "generationKeys");
        this.dpopKeys = Objects.requireNonNull(dpopKeys, "dpopKeys");
        this.passwordKeys = Objects.requireNonNull(passwordKeys, "passwordKeys");
        this.script = Objects.requireNonNull(script, "script");
    }

    @Override
    public PasswordReplayResult reserve(PasswordReplayAttempt attempt) {
        Objects.requireNonNull(attempt, "attempt");
        List<String> keys = new ArrayList<>(4);
        keys.add(generationKeys.control());
        keys.add(dpopKeys.forDpop(attempt.requestKey(), attempt.proofIds().dpop()));
        keys.add(passwordKeys.forRequestKey(attempt.requestKey(), attempt.proofIds().requestKey()));
        if (attempt.deviceKeyThumbprint() != null) {
            keys.add(passwordKeys.forDeviceKey(attempt.deviceKeyThumbprint(),
                    attempt.proofIds().deviceKey()));
        }
        try {
            String runId = identity.currentRunId();
            if (runId == null || runId.isBlank()) {
                return new PasswordReplayResult.AuthorityClosed();
            }
            String result = redis.execute(script, keys, runId);
            if (result != null && result.startsWith("RESERVED:")) {
                return new PasswordReplayResult.Reserved(
                        UUID.fromString(result.substring("RESERVED:".length())));
            }
            if ("REPLAYED".equals(result)) {
                return new PasswordReplayResult.Replayed();
            }
            return new PasswordReplayResult.AuthorityClosed();
        } catch (RuntimeException failure) {
            throw new ReplayAuthorityUnavailableException(failure);
        }
    }
}
