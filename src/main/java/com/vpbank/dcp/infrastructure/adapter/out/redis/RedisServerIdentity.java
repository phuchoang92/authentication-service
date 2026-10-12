package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.infrastructure.adapter.out.redis.key.RuntimeKeys;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.Objects;
import java.util.Properties;
import java.util.Optional;
import java.util.UUID;

/**
 * Reads the current primary's run ID; it is never cached across admissions.
 */
public final class RedisServerIdentity {

    private final StringRedisTemplate redis;
    private final RuntimeKeys keys;

    public RedisServerIdentity(StringRedisTemplate redis, RuntimeKeys keys) {
        this.redis = Objects.requireNonNull(redis, "redis");
        this.keys = Objects.requireNonNull(keys);
    }

    public String currentRunId() {
        return redis.execute((RedisCallback<String>) connection -> {
            Properties info = connection.serverCommands().info("server");
            return info == null ? null : info.getProperty("run_id");
        });
    }

    /** Called once at startup. Missing or restored old markers never authorize traffic. */
    public void initialize() {
        String runId = currentRunId();
        if (runId == null || runId.isBlank()) {
            throw new InvalidAuthorityRedisConfigurationException();
        }
        String proposed = runId + ":" + UUID.randomUUID();
        Boolean installed = redis.opsForValue().setIfAbsent(keys.marker(), proposed);
        if (!Boolean.TRUE.equals(installed)
                && currentGeneration().isEmpty()) {
            throw new InvalidAuthorityRedisConfigurationException();
        }
    }

    /** A restarted, flushed or promoted Redis instance invalidates earlier sessions. */
    public Optional<UUID> currentGeneration() {
        String runId = currentRunId();
        if (runId == null || runId.isBlank()) {
            return Optional.empty();
        }
        String marker = redis.opsForValue().get(keys.marker());
        if (marker == null || !marker.startsWith(runId + ":")) {
            return Optional.empty();
        }
        try {
            return Optional.of(UUID.fromString(marker.substring(runId.length() + 1)));
        } catch (IllegalArgumentException invalid) {
            return Optional.empty();
        }
    }
}
