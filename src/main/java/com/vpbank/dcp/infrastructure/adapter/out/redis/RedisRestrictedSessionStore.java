package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import com.vpbank.dcp.core.port.out.trusteddevice.KeyExchange;
import com.vpbank.dcp.core.port.out.trusteddevice.LoginKeys;
import com.vpbank.dcp.core.port.out.trusteddevice.PreparedRestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionStep;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionStore;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionUnavailableException;
import com.vpbank.dcp.core.port.out.trusteddevice.StoredRestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustTarget;
import com.vpbank.dcp.core.port.out.trusteddevice.WrappedServerKey;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Restricted sessions live in the same {@code session:v1:<version>:<lookup>} key space as ACTIVE
 * ones, so the BFF finds either from the App token. {@code state=NEED_TRUSTED_DEVICE} is what
 * tells them apart; nothing may treat a missing or unknown state as ACTIVE.
 *
 * <p>Integration-only, like {@link RedisSessionAuthority}: ordinary Redis commands, no script.
 * Each step is gated by one atomic command ({@code HSETNX}, {@code HINCRBY}, {@code DEL}). A gate
 * that ran on a key which had just expired would create a key without TTL; that key is deleted.
 */
public final class RedisRestrictedSessionStore implements RestrictedSessionStore {
    static final String STATE = "NEED_TRUSTED_DEVICE";

    private static final Set<String> BASE_FIELDS = Set.of("schemaVersion", "state", "step",
            "sessionId", "operationId", "subjectId", "customerNumber", "customerStatusVersion",
            "channel", "deviceIdDigest", "platform", "requestKeyJkt", "requestPublicJwk",
            "responsePublicJwk", "generation", "createdAtMs", "expiresAtMs", "verifyAttempts",
            "target");
    private static final Set<String> KNOWN_DEVICE_FIELDS =
            Set.of("deviceBindingId", "deviceKeyJkt", "deviceSecurityVersion");
    private static final Set<String> KEY_EXCHANGE_FIELDS = Set.of("keyExchangeStartedAtMs",
            "serverKeyId", "serverKeyCiphertext", "serverPublicJwk", "challengeDigest",
            "devicePublicJwk", "exchangeDeviceKeyJkt");
    private static final String MFA_FIELD = "mfaTransactionId";

    private final StringRedisTemplate redis;
    private final RedisServerIdentity identity;
    private final SessionKeys sessions = new SessionKeys();
    private final Clock clock;

    public RedisRestrictedSessionStore(StringRedisTemplate redis, RedisServerIdentity identity,
                                       Clock clock) {
        this.redis = Objects.requireNonNull(redis);
        this.identity = Objects.requireNonNull(identity);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public Optional<UUID> currentGeneration() {
        try {
            return identity.currentGeneration();
        } catch (RuntimeException failure) {
            return Optional.empty();
        }
    }

    @Override
    public boolean create(PreparedRestrictedSession prepared) {
        Objects.requireNonNull(prepared);
        String key = key(prepared.lookup());
        try {
            if (!clock.instant().isBefore(prepared.expiresAt())
                    || Boolean.TRUE.equals(redis.hasKey(key))) {
                return false;
            }
            Map<String, String> fields = fields(prepared);
            redis.opsForHash().putAll(key, fields);
            if (!Boolean.TRUE.equals(redis.expireAt(key, Date.from(prepared.expiresAt())))
                    || !stored(key, fields)) {
                redis.delete(key);
                return false;
            }
            return true;
        } catch (RuntimeException failure) {
            deleteQuietly(key);
            return false;
        }
    }

    @Override
    public Optional<StoredRestrictedSession> find(SessionTokenLookup session) {
        Objects.requireNonNull(session);
        Map<Object, Object> raw;
        try {
            raw = redis.opsForHash().entries(key(session));
        } catch (RuntimeException failure) {
            throw new RestrictedSessionUnavailableException(failure);
        }
        try {
            return decode(raw);
        } catch (RuntimeException corrupt) {
            // Anything that is not exactly this codec denies; it never degrades to a default.
            return Optional.empty();
        }
    }

    @Override
    public boolean beginKeyExchange(SessionTokenLookup session, KeyExchange exchange) {
        Objects.requireNonNull(session);
        Objects.requireNonNull(exchange);
        String key = key(session);
        try {
            if (!Boolean.TRUE.equals(redis.opsForHash().putIfAbsent(key, "keyExchangeStartedAtMs",
                    Long.toString(clock.millis())))) {
                return false;
            }
            if (!stillLive(key)) {
                return false;
            }
            Map<String, String> fields = new HashMap<>();
            fields.put("serverKeyId", exchange.serverKey().keyId());
            fields.put("serverKeyCiphertext", base64(exchange.serverKey().ciphertext()));
            fields.put("serverPublicJwk", exchange.serverPublicJwk());
            fields.put("challengeDigest", exchange.challengeDigest().base64Url());
            fields.put("devicePublicJwk", exchange.devicePublicJwk());
            fields.put("exchangeDeviceKeyJkt", exchange.deviceKeyThumbprint().base64Url());
            fields.put("step", RestrictedSessionStep.KEY_EXCHANGE.name());
            redis.opsForHash().putAll(key, fields);
            return true;
        } catch (RuntimeException failure) {
            throw new RestrictedSessionUnavailableException(failure);
        }
    }

    @Override
    public int recordVerifyAttempt(SessionTokenLookup session) {
        Objects.requireNonNull(session);
        String key = key(session);
        try {
            Long attempts = redis.opsForHash().increment(key, "verifyAttempts", 1);
            if (attempts == null || !stillLive(key)) {
                return -1;
            }
            return Math.toIntExact(attempts);
        } catch (RuntimeException failure) {
            throw new RestrictedSessionUnavailableException(failure);
        }
    }

    @Override
    public boolean recordMfaTransaction(SessionTokenLookup session, String mfaTransactionId) {
        Objects.requireNonNull(session);
        Objects.requireNonNull(mfaTransactionId);
        String key = key(session);
        try {
            if (!Boolean.TRUE.equals(redis.opsForHash().putIfAbsent(key, MFA_FIELD, mfaTransactionId))
                    || !stillLive(key)) {
                return false;
            }
            redis.opsForHash().put(key, "step", RestrictedSessionStep.MFA.name());
            return true;
        } catch (RuntimeException failure) {
            throw new RestrictedSessionUnavailableException(failure);
        }
    }

    @Override
    public boolean consume(SessionTokenLookup session) {
        Objects.requireNonNull(session);
        try {
            Long deleted = redis.delete(java.util.List.of(key(session)));
            return deleted != null && deleted == 1;
        } catch (RuntimeException failure) {
            throw new RestrictedSessionUnavailableException(failure);
        }
    }

    /** A gate that hit an expired key created a key with no TTL: remove it and fail the step. */
    private boolean stillLive(String key) {
        Long ttl = redis.getExpire(key, TimeUnit.MILLISECONDS);
        if (ttl == null || ttl <= 0) {
            deleteQuietly(key);
            return false;
        }
        return true;
    }

    private Optional<StoredRestrictedSession> decode(Map<Object, Object> raw) {
        if (raw.isEmpty()) {
            return Optional.empty();
        }
        Map<String, String> f = new HashMap<>();
        raw.forEach((name, value) -> f.put((String) name, (String) value));
        if (!"1".equals(f.get("schemaVersion")) || !STATE.equals(f.get("state"))) {
            return Optional.empty();
        }
        RestrictedSessionStep step = RestrictedSessionStep.valueOf(f.get("step"));
        boolean known = switch (f.get("target")) {
            case "KNOWN_DEVICE" -> true;
            case "NEW_DEVICE" -> false;
            default -> throw new IllegalStateException();
        };
        Set<String> expected = new HashSet<>(BASE_FIELDS);
        if (known) {
            expected.addAll(KNOWN_DEVICE_FIELDS);
        }
        if (step != RestrictedSessionStep.OPEN) {
            expected.addAll(KEY_EXCHANGE_FIELDS);
        }
        if (step == RestrictedSessionStep.MFA) {
            expected.add(MFA_FIELD);
        }
        if (!expected.equals(f.keySet())) {
            return Optional.empty();
        }
        Instant expiresAt = Instant.ofEpochMilli(Long.parseLong(f.get("expiresAtMs")));
        if (!clock.instant().isBefore(expiresAt)) {
            return Optional.empty();
        }
        TrustTarget target = known
                ? new TrustTarget.KnownDevice(new BindingId(UUID.fromString(f.get("deviceBindingId"))),
                        Digest32.fromBase64Url(f.get("deviceKeyJkt")),
                        Long.parseLong(f.get("deviceSecurityVersion")))
                : new TrustTarget.NewDevice();
        KeyExchange exchange = step == RestrictedSessionStep.OPEN ? null : new KeyExchange(
                new WrappedServerKey(f.get("serverKeyId"),
                        Base64.getUrlDecoder().decode(f.get("serverKeyCiphertext"))),
                f.get("serverPublicJwk"), Digest32.fromBase64Url(f.get("challengeDigest")),
                f.get("devicePublicJwk"), Digest32.fromBase64Url(f.get("exchangeDeviceKeyJkt")));
        return Optional.of(new StoredRestrictedSession(UUID.fromString(f.get("sessionId")),
                UUID.fromString(f.get("operationId")),
                new SubjectId(UUID.fromString(f.get("subjectId"))),
                new CustomerNumber(f.get("customerNumber")),
                Long.parseLong(f.get("customerStatusVersion")), f.get("channel"), target,
                Digest32.fromBase64Url(f.get("deviceIdDigest")),
                new LoginKeys(f.get("requestPublicJwk"), Digest32.fromBase64Url(f.get("requestKeyJkt")),
                        f.get("responsePublicJwk")),
                f.get("platform"), UUID.fromString(f.get("generation")), expiresAt, step,
                Integer.parseInt(f.get("verifyAttempts")), exchange, f.get(MFA_FIELD)));
    }

    private boolean stored(String key, Map<String, String> expected) {
        Long ttl = redis.getExpire(key, TimeUnit.MILLISECONDS);
        Map<Object, Object> actual = redis.opsForHash().entries(key);
        return ttl != null && ttl > 0 && expected.equals(actual);
    }

    private void deleteQuietly(String key) {
        try {
            redis.delete(key);
        } catch (RuntimeException ignored) {
            // The key expires on its own; a token that was never delivered cannot use it.
        }
    }

    private String key(SessionTokenLookup lookup) {
        return sessions.forLookup(lookup.version(), lookup.digest());
    }

    private static String base64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private Map<String, String> fields(PreparedRestrictedSession prepared) {
        RestrictedSession session = prepared.session();
        Map<String, String> fields = new HashMap<>();
        fields.put("schemaVersion", "1");
        fields.put("state", STATE);
        fields.put("step", RestrictedSessionStep.OPEN.name());
        fields.put("sessionId", prepared.sessionId().toString());
        fields.put("operationId", session.operationId().toString());
        fields.put("subjectId", session.owner().value().toString());
        fields.put("customerNumber", session.customerNumber().value());
        fields.put("customerStatusVersion", Long.toString(session.customerStatusVersion()));
        fields.put("channel", session.channel());
        fields.put("deviceIdDigest", prepared.deviceIdDigest().base64Url());
        fields.put("platform", session.platform());
        fields.put("requestKeyJkt", session.keys().requestKeyThumbprint().base64Url());
        fields.put("requestPublicJwk", session.keys().requestPublicJwk());
        fields.put("responsePublicJwk", session.keys().responsePublicJwk());
        fields.put("generation", session.generation().toString());
        fields.put("createdAtMs", Long.toString(clock.millis()));
        fields.put("expiresAtMs", Long.toString(prepared.expiresAt().toEpochMilli()));
        fields.put("verifyAttempts", "0");
        // Missing and empty differ (contract 16): a new device has no binding fields at all.
        switch (session.target()) {
            case TrustTarget.NewDevice() -> fields.put("target", "NEW_DEVICE");
            case TrustTarget.KnownDevice known -> {
                fields.put("target", "KNOWN_DEVICE");
                fields.put("deviceBindingId", known.bindingId().value().toString());
                fields.put("deviceKeyJkt", known.deviceKeyThumbprint().base64Url());
                fields.put("deviceSecurityVersion", Long.toString(known.deviceSecurityVersion()));
            }
        }
        return fields;
    }
}
