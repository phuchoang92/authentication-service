package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.port.out.authority.AuthorityControl;
import com.vpbank.dcp.core.port.out.authority.AuthorityControlUnavailableException;
import com.vpbank.dcp.core.port.out.authority.ControlCloseResult;
import com.vpbank.dcp.core.port.out.authority.ControlClosure;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GenerationKeys;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.util.List;
import java.util.Objects;

/**
 * A fenced, exact-generation close; this adapter cannot publish READY.
 */
public final class RedisAuthorityControl implements AuthorityControl {

    private final StringRedisTemplate redis;
    private final RedisServerIdentity identity;
    private final GenerationKeys generationKeys;
    private final DefaultRedisScript<String> script;

    public RedisAuthorityControl(StringRedisTemplate redis, RedisServerIdentity identity,
                                 GenerationKeys generationKeys, DefaultRedisScript<String> script) {
        this.redis = Objects.requireNonNull(redis, "redis");
        this.identity = Objects.requireNonNull(identity, "identity");
        this.generationKeys = Objects.requireNonNull(generationKeys, "generationKeys");
        this.script = Objects.requireNonNull(script, "script");
    }

    @Override
    public ControlCloseResult close(ControlClosure closure) {
        Objects.requireNonNull(closure, "closure");
        try {
            String runId = identity.currentRunId();
            if (runId == null || runId.isBlank()) {
                return ControlCloseResult.AUTHORITY_CLOSED;
            }
            String outcome = redis.execute(script, List.of(generationKeys.control()),
                    closure.generation().toString(), runId,
                    Long.toString(closure.controllerFence()));
            return switch (outcome) {
                case "CLOSED" -> ControlCloseResult.CLOSED;
                case "ALREADY_CLOSED" -> ControlCloseResult.ALREADY_CLOSED;
                default -> ControlCloseResult.AUTHORITY_CLOSED;
            };
        } catch (RuntimeException failure) {
            throw new AuthorityControlUnavailableException(failure);
        }
    }
}
