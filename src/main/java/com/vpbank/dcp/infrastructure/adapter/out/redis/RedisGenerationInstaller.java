package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.port.out.authority.AuthorityControlUnavailableException;
import com.vpbank.dcp.core.port.out.authority.ClosedGeneration;
import com.vpbank.dcp.core.port.out.authority.GenerationInstallResult;
import com.vpbank.dcp.core.port.out.authority.GenerationInstaller;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GenerationKeys;
import java.util.List;
import java.util.Objects;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

/** Installs a new generation as CLOSED; it cannot reopen serving authority. */
public final class RedisGenerationInstaller implements GenerationInstaller {

    private final StringRedisTemplate redis;
    private final RedisServerIdentity identity;
    private final GenerationKeys keys;
    private final DefaultRedisScript<String> script;

    public RedisGenerationInstaller(StringRedisTemplate redis, RedisServerIdentity identity,
                                    GenerationKeys keys, DefaultRedisScript<String> script) {
        this.redis = Objects.requireNonNull(redis, "redis");
        this.identity = Objects.requireNonNull(identity, "identity");
        this.keys = Objects.requireNonNull(keys, "keys");
        this.script = Objects.requireNonNull(script, "script");
    }

    @Override
    public GenerationInstallResult installClosed(ClosedGeneration command) {
        Objects.requireNonNull(command, "command");
        try {
            String runId = identity.currentRunId();
            if (runId == null || runId.isBlank()) {
                return GenerationInstallResult.AUTHORITY_CLOSED;
            }
            String outcome = redis.execute(script, List.of(keys.control()),
                    command.generation().toString(), runId, command.controllerId().toString(),
                    Long.toString(command.fence()), Long.toString(command.leaseUntil().toEpochMilli()));
            return switch (outcome) {
                case "INSTALLED" -> GenerationInstallResult.INSTALLED;
                case "ALREADY_INSTALLED" -> GenerationInstallResult.ALREADY_INSTALLED;
                case "STALE" -> GenerationInstallResult.STALE;
                default -> GenerationInstallResult.AUTHORITY_CLOSED;
            };
        } catch (RuntimeException failure) {
            throw new AuthorityControlUnavailableException(failure);
        }
    }
}
