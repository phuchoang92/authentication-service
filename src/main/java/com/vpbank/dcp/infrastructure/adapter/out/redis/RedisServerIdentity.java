package com.vpbank.dcp.infrastructure.adapter.out.redis;

import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.Objects;
import java.util.Properties;

/**
 * Reads the current primary's run ID; it is never cached across admissions.
 */
public final class RedisServerIdentity {

    private final StringRedisTemplate redis;

    public RedisServerIdentity(StringRedisTemplate redis) {
        this.redis = Objects.requireNonNull(redis, "redis");
    }

    public String currentRunId() {
        return redis.execute((RedisCallback<String>) connection -> {
            Properties info = connection.serverCommands().info("server");
            return info == null ? null : info.getProperty("run_id");
        });
    }
}
