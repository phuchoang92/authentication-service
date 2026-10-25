package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.customer.CustomerNumber;
import com.vpbank.dcp.core.customer.SubjectId;
import com.vpbank.dcp.core.device.BindingId;
import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.session.KeyExchange;
import com.vpbank.dcp.core.session.LoginKeys;
import com.vpbank.dcp.core.session.PreparedRestrictedSession;
import com.vpbank.dcp.core.session.RestrictedSession;
import com.vpbank.dcp.core.session.RestrictedSessionStep;
import com.vpbank.dcp.core.session.RestrictedSessionStore;
import com.vpbank.dcp.core.session.RestrictedSessionUnavailableException;
import com.vpbank.dcp.core.session.PinnedCustomer;
import com.vpbank.dcp.core.session.PinnedDevice;
import com.vpbank.dcp.core.session.RestrictedProgress;
import com.vpbank.dcp.core.session.StoredRestrictedSession;
import com.vpbank.dcp.core.session.TrustTarget;
import com.vpbank.dcp.core.session.WrappedServerKey;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Restricted sessions live in the same {@code session:v2:<sessionId>} key space as ACTIVE ones,
 * so the BFF finds either from the App token. {@code state=NEED_TRUSTED_DEVICE} is what
 * tells them apart; nothing may treat a missing or unknown state as ACTIVE.
 *
 * <p>Integration-only, like {@link RedisSessionAuthority}: ordinary Redis commands, no script.
 * Creation is one {@code MULTI/EXEC} with the session-list entry. Each later step is gated by
 * one atomic command ({@code HSETNX}, {@code HINCRBY}, {@code DEL}). A gate
 * that ran on a key which had just expired would create a key without TTL; that key is deleted.
 */
public final class RedisRestrictedSessionStore implements RestrictedSessionStore {
    static final String STATE = "NEED_TRUSTED_DEVICE";

    private static final Set<String> BASE_FIELDS = Set.of("schemaVersion", "state", "step",
            "sessionId", "secretDigest", "operationId", "subjectId", "customerNumber", "customerStatusVersion",
            "channel", "deviceIdDigest", "platform", "requestKeyJkt", "requestPublicJwk",
            "responsePublicJwk", "generation", "createdAtMs", "expiresAtMs", "verifyAttempts",
            "target");
    private static final Set<String> KNOWN_DEVICE_FIELDS =
            Set.of("deviceBindingId", "deviceKeyJkt", "deviceSecurityVersion");
    private static final Set<String> KEY_EXCHANGE_FIELDS = Set.of("keyExchangeStartedAtMs",
            "serverKeyId", "serverKeyCiphertext", "serverPublicKey", "challengeDigest",
            "devicePublicKey", "exchangeDeviceKeyJkt", "enrollmentId");
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

    /** The session and its entry in the Customer's session list are written in one transaction. */
    @Override
    public boolean create(PreparedRestrictedSession prepared) {
        Objects.requireNonNull(prepared);
        RestrictedSession session = prepared.session();
        String key = key(prepared.sessionId());
        String listKey = sessions.forSubjectSessions(session.device().channel(), session.customer().owner());
        String binding = switch (session.device().target()) {
            case TrustTarget.KnownDevice known -> known.bindingId().value().toString();
            case TrustTarget.NewDevice() -> "-";
        };
        Map<String, String> listEntry = Map.of(prepared.sessionId().toString(), "v1|" + binding);
        Map<String, String> fields = fields(prepared);
        try {
            if (!clock.instant().isBefore(prepared.expiresAt())) {
                return false;
            }
            Boolean written = redis.execute(new SessionCallback<Boolean>() {
                @Override
                @SuppressWarnings("unchecked")
                public Boolean execute(RedisOperations operations) throws DataAccessException {
                    RedisOperations<String, String> ops = operations;
                    ops.watch(key);
                    if (Boolean.TRUE.equals(ops.hasKey(key))) {
                        ops.unwatch();
                        return false;
                    }
                    ops.multi();
                    ops.opsForHash().putAll(key, fields);
                    ops.expireAt(key, Date.from(prepared.expiresAt()));
                    // HSET + per-field HPEXPIREAT rather than HSETEX: same effect inside MULTI, and
                    // available on every server this build is tested against.
                    ops.opsForHash().putAll(listKey, listEntry);
                    ops.opsForHash().expireAt(listKey, prepared.expiresAt(), List.<Object>copyOf(listEntry.keySet()));
                    List<Object> applied = ops.exec();
                    return applied != null && !applied.isEmpty();
                }
            });
            return Boolean.TRUE.equals(written) && stored(key, fields);
        } catch (RuntimeException failure) {
            // EXEC may have run; a token that is never delivered cannot use what it left.
            return false;
        }
    }

    @Override
    public Optional<StoredRestrictedSession> find(UUID sessionId) {
        Objects.requireNonNull(sessionId);
        Map<Object, Object> raw;
        try {
            raw = redis.opsForHash().entries(key(sessionId));
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
    public boolean beginKeyExchange(UUID sessionId, KeyExchange exchange) {
        Objects.requireNonNull(sessionId);
        Objects.requireNonNull(exchange);
        String key = key(sessionId);
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
            fields.put("serverPublicKey", exchange.serverPublicKey());
            fields.put("challengeDigest", exchange.challengeDigest().base64Url());
            fields.put("devicePublicKey", exchange.devicePublicKey());
            fields.put("exchangeDeviceKeyJkt", exchange.deviceKeyThumbprint().base64Url());
            fields.put("enrollmentId", exchange.enrollmentId().toString());
            fields.put("step", RestrictedSessionStep.KEY_EXCHANGE.name());
            redis.opsForHash().putAll(key, fields);
            return true;
        } catch (RuntimeException failure) {
            throw new RestrictedSessionUnavailableException(failure);
        }
    }

    @Override
    public int recordVerifyAttempt(UUID sessionId) {
        Objects.requireNonNull(sessionId);
        String key = key(sessionId);
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
    public boolean recordMfaTransaction(UUID sessionId, String mfaTransactionId) {
        Objects.requireNonNull(sessionId);
        Objects.requireNonNull(mfaTransactionId);
        String key = key(sessionId);
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
    public boolean consume(UUID sessionId) {
        Objects.requireNonNull(sessionId);
        try {
            Long deleted = redis.delete(List.of(key(sessionId)));
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
                f.get("serverPublicKey"), Digest32.fromBase64Url(f.get("challengeDigest")),
                f.get("devicePublicKey"), Digest32.fromBase64Url(f.get("exchangeDeviceKeyJkt")),
                UUID.fromString(f.get("enrollmentId")));
        RestrictedSession login = new RestrictedSession(UUID.fromString(f.get("operationId")),
                new PinnedCustomer(new SubjectId(UUID.fromString(f.get("subjectId"))),
                        new CustomerNumber(f.get("customerNumber")),
                        Long.parseLong(f.get("customerStatusVersion"))),
                new PinnedDevice(f.get("channel"), f.get("platform"), target),
                new LoginKeys(f.get("requestPublicJwk"), Digest32.fromBase64Url(f.get("requestKeyJkt")),
                        f.get("responsePublicJwk")),
                UUID.fromString(f.get("generation")));
        return Optional.of(new StoredRestrictedSession(UUID.fromString(f.get("sessionId")), login,
                Digest32.fromBase64Url(f.get("deviceIdDigest")), expiresAt,
                new RestrictedProgress(step, Integer.parseInt(f.get("verifyAttempts")), exchange,
                        f.get(MFA_FIELD))));
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

    private String key(UUID sessionId) {
        return sessions.forSession(sessionId);
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
        fields.put("secretDigest", prepared.secretDigest().base64Url());
        fields.put("operationId", session.operationId().toString());
        fields.put("subjectId", session.customer().owner().value().toString());
        fields.put("customerNumber", session.customer().number().value());
        fields.put("customerStatusVersion", Long.toString(session.customer().statusVersion()));
        fields.put("channel", session.device().channel());
        fields.put("deviceIdDigest", prepared.deviceIdDigest().base64Url());
        fields.put("platform", session.device().platform());
        fields.put("requestKeyJkt", session.keys().requestKeyThumbprint().base64Url());
        fields.put("requestPublicJwk", session.keys().requestPublicJwk());
        fields.put("responsePublicJwk", session.keys().responsePublicJwk());
        fields.put("generation", session.generation().toString());
        fields.put("createdAtMs", Long.toString(clock.millis()));
        fields.put("expiresAtMs", Long.toString(prepared.expiresAt().toEpochMilli()));
        fields.put("verifyAttempts", "0");
        // Missing and empty differ (contract 16): a new device has no binding fields at all.
        switch (session.device().target()) {
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
