package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import io.lettuce.core.api.StatefulConnection;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettucePoolingClientConfiguration;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.types.RedisClientInfo;
import org.testcontainers.containers.GenericContainer;

/**
 * A pooled connection factory as the application configures it, for the Valkey adapter tests: the pool holds the
 * shared connection every ordinary command uses, and the connections a {@code WATCH … EXEC} runs on.
 */
final class PooledValkey {
    /** Names the pooled connections, so a test can tell them from every other client of the server. */
    private static final String CLIENT_NAME = "pool-under-test";

    private PooledValkey() {
    }

    static LettuceConnectionFactory connections(GenericContainer<?> valkey, int size, Duration maxWait) {
        GenericObjectPoolConfig<StatefulConnection<?, ?>> pool = new GenericObjectPoolConfig<>();
        pool.setMaxTotal(size);
        pool.setMaxIdle(size);
        pool.setMaxWait(maxWait);
        LettuceConnectionFactory connections = new LettuceConnectionFactory(
                new RedisStandaloneConfiguration(valkey.getHost(), valkey.getMappedPort(6379)),
                LettucePoolingClientConfiguration.builder().poolConfig(pool).clientName(CLIENT_NAME).build());
        connections.afterPropertiesSet();
        return connections;
    }

    /** The server-side IDs of the pool's connections ({@code CLIENT LIST}); a reconnect shows as a new ID. */
    static Set<String> connectionIdsOf(StringRedisTemplate template) {
        List<RedisClientInfo> clients = template.execute(
                (RedisCallback<List<RedisClientInfo>>) connection -> connection.serverCommands().getClientList());
        return clients.stream()
                .filter(client -> CLIENT_NAME.equals(client.getName()))
                .map(client -> client.get("id"))
                .collect(Collectors.toSet());
    }

    /**
     * Takes one {@code WATCH … EXEC} connection out of the pool, as a compare-and-set in flight does, and keeps
     * it until the returned handle is closed.
     */
    static HeldConnection holdWriteConnection(StringRedisTemplate template) throws InterruptedException {
        CountDownLatch held = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Thread holder = new Thread(() -> template.execute(new SessionCallback<Object>() {
            @Override
            @SuppressWarnings("unchecked")
            public <K, V> Object execute(RedisOperations<K, V> operations) {
                var ops = (RedisOperations<String, String>) operations;
                ops.watch("pool-holder");
                held.countDown();
                awaitQuietly(release);
                ops.unwatch();
                return null;
            }
        }));
        holder.start();
        if (!held.await(5, TimeUnit.SECONDS)) {
            throw new IllegalStateException("The pool gave no write connection to hold");
        }
        return () -> {
            release.countDown();
            holder.join(5_000);
        };
    }

    /** Gives the held connection back to the pool. */
    interface HeldConnection extends AutoCloseable {
        @Override
        void close() throws InterruptedException;
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
