package com.vpbank.dcp.infrastructure.adapter.out.redis;

import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.Objects;
import java.util.Properties;

/**
 * Rejects unsafe authority storage before the private service starts accepting traffic.
 */
public final class AuthorityRedisPreflight {

    private final StringRedisTemplate redis;

    public AuthorityRedisPreflight(StringRedisTemplate redis) {
        this.redis = Objects.requireNonNull(redis, "redis");
    }

    public void verify() {
        try {
            Boolean safe = redis.execute((RedisCallback<Boolean>) connection -> {
                Properties memoryPolicy = connection.serverCommands().getConfig("maxmemory-policy");
                Properties memoryLimit = connection.serverCommands().getConfig("maxmemory");
                Properties replication = connection.serverCommands().info("replication");
                Properties server = connection.serverCommands().info("server");
                Properties cluster = connection.serverCommands().info("cluster");
                return memoryPolicy != null && memoryLimit != null
                        && replication != null && server != null && cluster != null
                        && "noeviction".equals(memoryPolicy.getProperty("maxmemory-policy"))
                        && positiveMemoryLimit(memoryLimit.getProperty("maxmemory"))
                        && "master".equals(replication.getProperty("role"))
                        && "0".equals(cluster.getProperty("cluster_enabled"))
                        && server.getProperty("run_id") != null
                        && !server.getProperty("run_id").isBlank();
            });
            if (!Boolean.TRUE.equals(safe)) {
                throw new InvalidAuthorityRedisConfigurationException();
            }
        } catch (RuntimeException failure) {
            if (failure instanceof InvalidAuthorityRedisConfigurationException) {
                throw failure;
            }
            throw new InvalidAuthorityRedisConfigurationException(failure);
        }
    }

    private boolean positiveMemoryLimit(String value) {
        if (value == null || !value.matches("[0-9]{1,16}")) {
            return false;
        }
        return Long.parseLong(value) > 0;
    }
}
