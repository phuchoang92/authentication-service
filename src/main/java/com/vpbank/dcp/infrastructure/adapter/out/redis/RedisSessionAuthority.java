package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.port.out.session.SessionAuthority;
import com.vpbank.dcp.core.port.out.session.SessionActivationFacts;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.session.SessionApplyResult;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.NonceKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.springframework.data.redis.core.StringRedisTemplate;

/** Integration-only session publication using ordinary Redis commands. */
public final class RedisSessionAuthority implements SessionAuthority {

    private final StringRedisTemplate redis;
    private final RedisServerIdentity identity;
    private final SessionKeys sessions = new SessionKeys();
    private final NonceKeys nonces;
    private final Duration nonceValidity;
    private final Clock clock;
    private final Sha256Digests digests = new Sha256Digests();

    public RedisSessionAuthority(StringRedisTemplate redis, RedisServerIdentity identity,
                                         AuthorityScope scope, Duration nonceValidity, Clock clock) {
        this.redis = Objects.requireNonNull(redis);
        this.identity = Objects.requireNonNull(identity);
        this.nonces = new NonceKeys(Objects.requireNonNull(scope));
        this.nonceValidity = Objects.requireNonNull(nonceValidity);
        this.clock = Objects.requireNonNull(clock);
        if (nonceValidity.toMillis() < 1000 || nonceValidity.toMillis() > 120000) {
            throw new InvalidAuthorityRedisConfigurationException();
        }
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
    public SessionApplyResult apply(PreparedSession session) {
        Objects.requireNonNull(session);
        try {
            if (!isCurrent(session)) {
                return SessionApplyResult.AUTHORITY_CLOSED;
            }
            String sessionKey = sessionKey(session);
            if (Boolean.TRUE.equals(redis.hasKey(sessionKey))) {
                return deliverable(session) ? SessionApplyResult.ALREADY_APPLIED
                        : SessionApplyResult.AUTHORITY_CLOSED;
            }
            redis.opsForHash().putAll(sessionKey, sessionFields(session));
            if (!Boolean.TRUE.equals(redis.expireAt(sessionKey,
                    Date.from(session.deadlines().idleExpiresAt())))) {
                return SessionApplyResult.AUTHORITY_CLOSED;
            }
            String nonceKey = nonces.forFamily(session.sessionId());
            redis.opsForHash().putAll(nonceKey, nonceFields(session));
            if (!Boolean.TRUE.equals(redis.expireAt(nonceKey,
                    Date.from(session.deadlines().absoluteExpiresAt())))) {
                return SessionApplyResult.AUTHORITY_CLOSED;
            }
            return deliverable(session) ? SessionApplyResult.APPLIED
                    : SessionApplyResult.AUTHORITY_CLOSED;
        } catch (RuntimeException failure) {
            return SessionApplyResult.AUTHORITY_CLOSED;
        }
    }

    @Override
    public boolean deliverable(PreparedSession session) {
        Objects.requireNonNull(session);
        try {
            if (!isCurrent(session)) {
                return false;
            }
            Map<Object, Object> stored = redis.opsForHash().entries(sessionKey(session));
            Map<Object, Object> nonce = redis.opsForHash().entries(
                    nonces.forFamily(session.sessionId()));
            Long sessionTtl = redis.getExpire(sessionKey(session), TimeUnit.MILLISECONDS);
            Long nonceTtl = redis.getExpire(nonces.forFamily(session.sessionId()),
                    TimeUnit.MILLISECONDS);
            return sessionTtl != null && sessionTtl > 0
                    && nonceTtl != null && nonceTtl > 0
                    && stored.size() == 23 && nonce.size() == 9
                    && "1".equals(stored.get("schemaVersion"))
                    && "ACTIVE".equals(stored.get("state"))
                    && session.sessionId().toString().equals(stored.get("sessionId"))
                    && session.generation().toString().equals(stored.get("generation"))
                    && session.facts().subjectId().toString().equals(stored.get("subjectId"))
                    && session.facts().bindingId().toString().equals(stored.get("deviceBindingId"))
                    && session.facts().requestKey().base64Url().equals(stored.get("requestKeyJkt"))
                    && "1".equals(nonce.get("schemaVersion"))
                    && session.sessionId().toString().equals(nonce.get("familyId"));
        } catch (RuntimeException failure) {
            return false;
        }
    }

    private boolean isCurrent(PreparedSession session) {
        Instant now = clock.instant();
        return session.generation().equals(identity.currentGeneration().orElse(null))
                && now.isBefore(session.deadlines().idleExpiresAt())
                && now.isBefore(session.deadlines().absoluteExpiresAt())
                && now.isBefore(session.deliveryDeadline())
                && now.isBefore(session.facts().customerStatusValidUntil());
    }

    private String sessionKey(PreparedSession session) {
        return sessions.forLookup(session.lookupVersion(), session.lookupDigest());
    }

    private Map<String, String> sessionFields(PreparedSession session) {
        SessionActivationFacts facts = session.facts();
        Map<String, String> fields = new HashMap<>();
        fields.put("schemaVersion", "1");
        fields.put("state", "ACTIVE");
        fields.put("sessionId", session.sessionId().toString());
        fields.put("subjectId", facts.subjectId().toString());
        fields.put("appId", facts.appId());
        fields.put("audience", facts.appId());
        fields.put("channel", "MOBILE");
        fields.put("scope", "[\"banking\"]");
        fields.put("deviceBindingId", facts.bindingId().toString());
        fields.put("requestKeyJkt", facts.requestKey().base64Url());
        fields.put("requestPublicJwk", facts.requestPublicJwk());
        fields.put("generation", session.generation().toString());
        fields.put("customerSecurityVersion", Long.toString(facts.customerSecurityVersion()));
        fields.put("credentialSecurityVersion", Long.toString(facts.credentialSecurityVersion()));
        fields.put("deviceSecurityVersion", Long.toString(facts.deviceSecurityVersion()));
        fields.put("sessionVersion", "0");
        fields.put("customerStatusVersion", Long.toString(facts.customerStatusVersion()));
        fields.put("customerStatusValidUntilMs",
                Long.toString(facts.customerStatusValidUntil().toEpochMilli()));
        fields.put("createdAtMs", Long.toString(clock.millis()));
        fields.put("idleExpiresAtMs", Long.toString(session.deadlines().idleExpiresAt().toEpochMilli()));
        fields.put("absoluteExpiresAtMs", Long.toString(session.deadlines().absoluteExpiresAt().toEpochMilli()));
        fields.put("nonceFamilyId", session.sessionId().toString());
        var assurance = facts.assurance();
        fields.put("assurance", "{\"biometricEnforcement\":\"" + assurance.biometricEnforcement().code()
                + "\",\"devicePossession\":\"" + assurance.devicePossession().code()
                + "\",\"platformEvidence\":\"" + assurance.platformEvidence().code() + "\"}");
        return fields;
    }

    private Map<String, String> nonceFields(PreparedSession session) {
        String digest = digests.sha256(session.dpopNonce().getBytes(StandardCharsets.US_ASCII))
                .base64Url();
        Instant expiry = clock.instant().plus(nonceValidity);
        if (expiry.isAfter(session.deadlines().absoluteExpiresAt())) {
            expiry = session.deadlines().absoluteExpiresAt();
        }
        return Map.of("schemaVersion", "1", "familyId", session.sessionId().toString(),
                "requestKeyJkt", session.facts().requestKey().base64Url(),
                "familyVersion", "0", "currentDigest", digest,
                "currentExpiresAtMs", Long.toString(expiry.toEpochMilli()),
                "previousDigest", "", "previousExpiresAtMs", "0",
                "familyDeadlineMs", Long.toString(session.deadlines().absoluteExpiresAt().toEpochMilli()));
    }
}
