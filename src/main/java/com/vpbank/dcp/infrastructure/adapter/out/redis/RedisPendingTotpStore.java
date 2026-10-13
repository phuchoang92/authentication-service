package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.port.out.pending.PendingTotpLogin;
import com.vpbank.dcp.core.port.out.pending.PendingTotpStore;
import com.vpbank.dcp.core.port.out.pending.PendingTotpUnavailableException;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.PendingTotpKeys;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.springframework.data.redis.core.StringRedisTemplate;
import tools.jackson.databind.json.JsonMapper;

/** Restricted login context uses SET NX with an expiry and single-use GETDEL on success. */
public final class RedisPendingTotpStore implements PendingTotpStore {
    private static final String FORMAT_PREFIX = "1|";
    private static final Duration MAX_LIFETIME = Duration.ofMinutes(15);

    private final StringRedisTemplate redis;
    private final RedisServerIdentity identity;
    private final JsonMapper json;
    private final Clock clock;
    private final PendingTotpKeys keys = new PendingTotpKeys();

    public RedisPendingTotpStore(StringRedisTemplate redis, RedisServerIdentity identity,
                                 JsonMapper json, Clock clock) {
        this.redis = Objects.requireNonNull(redis);
        this.identity = Objects.requireNonNull(identity);
        this.json = Objects.requireNonNull(json);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public boolean create(SessionTokenLookup token, PendingTotpLogin pending) {
        Objects.requireNonNull(token);
        Objects.requireNonNull(pending);
        Duration ttl = Duration.between(clock.instant(), pending.challenge().expiresAt());
        if (ttl.isNegative() || ttl.isZero() || ttl.compareTo(MAX_LIFETIME) > 0) {
            return false;
        }
        try {
            if (!pending.versions().generation().equals(identity.currentGeneration().orElse(null))) {
                return false;
            }
            String encoded = FORMAT_PREFIX + json.writeValueAsString(pending);
            return Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(keys.forToken(token), encoded, ttl));
        } catch (RuntimeException failure) {
            throw new PendingTotpUnavailableException();
        }
    }

    @Override
    public Optional<PendingTotpLogin> find(SessionTokenLookup token) {
        Objects.requireNonNull(token);
        try {
            String key = keys.forToken(token);
            Long ttl = redis.getExpire(key, TimeUnit.MILLISECONDS);
            if (ttl == null || ttl <= 0) {
                return Optional.empty();
            }
            return decode(redis.opsForValue().get(key));
        } catch (RuntimeException failure) {
            throw new PendingTotpUnavailableException();
        }
    }

    @Override
    public Optional<PendingTotpLogin> consume(SessionTokenLookup token) {
        Objects.requireNonNull(token);
        try {
            return decode(redis.opsForValue().getAndDelete(keys.forToken(token)));
        } catch (RuntimeException failure) {
            throw new PendingTotpUnavailableException();
        }
    }

    private Optional<PendingTotpLogin> decode(String encoded) {
        if (encoded == null) {
            return Optional.empty();
        }
        if (!encoded.startsWith(FORMAT_PREFIX)) {
            throw new PendingTotpUnavailableException();
        }
        PendingTotpLogin pending = json.readValue(encoded.substring(FORMAT_PREFIX.length()),
                PendingTotpLogin.class);
        if (!pending.versions().generation().equals(identity.currentGeneration().orElse(null))
                || !clock.instant().isBefore(pending.challenge().expiresAt())) {
            return Optional.empty();
        }
        return Optional.of(pending);
    }
}
