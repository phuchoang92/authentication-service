package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.domain.session.SessionAssurance;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.session.SessionActivationSnapshot;
import com.vpbank.dcp.core.port.out.session.SessionActivationContext;
import com.vpbank.dcp.core.port.out.session.SessionKeyBindings;
import com.vpbank.dcp.core.port.out.session.SessionSecurityVersions;
import com.vpbank.dcp.core.port.out.session.CustomerStatusFreshness;
import com.vpbank.dcp.core.port.out.session.SessionApplyResult;
import com.vpbank.dcp.core.port.out.session.SessionAuthority;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.NonceKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Integration-only session publication using ordinary Redis commands.
 */
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
            if (isCurrent(session)) {
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
            String nonceKey = nonces.forFamily(session.candidate().sessionId());
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
            if (isCurrent(session)) {
                return false;
            }
            Map<Object, Object> stored = redis.opsForHash().entries(sessionKey(session));
            Map<Object, Object> nonce = redis.opsForHash().entries(
                    nonces.forFamily(session.candidate().sessionId()));
            Long sessionTtl = redis.getExpire(sessionKey(session), TimeUnit.MILLISECONDS);
            Long nonceTtl = redis.getExpire(nonces.forFamily(session.candidate().sessionId()),
                    TimeUnit.MILLISECONDS);
            return sessionTtl != null && sessionTtl > 0
                    && nonceTtl != null && nonceTtl > 0
                    && stored.size() == 23 && nonce.size() == 9
                    && "1".equals(stored.get("schemaVersion"))
                    && "ACTIVE".equals(stored.get("state"))
                    && session.candidate().sessionId().toString().equals(stored.get("sessionId"))
                    && session.candidate().generation().toString().equals(stored.get("generation"))
                    && session.snapshot().context().subject().value().toString().equals(stored.get("subjectId"))
                    && session.snapshot().context().bindingId().value().toString().equals(stored.get("deviceBindingId"))
                    && session.snapshot().keys().requestKey().base64Url().equals(stored.get("requestKeyJkt"))
                    && "1".equals(nonce.get("schemaVersion"))
                    && session.candidate().sessionId().toString().equals(nonce.get("familyId"));
        } catch (RuntimeException failure) {
            return false;
        }
    }

    @Override
    public boolean revoke(PreparedSession session) {
        Objects.requireNonNull(session);
        try {
            String sessionKey = sessionKey(session);
            String nonceKey = nonces.forFamily(session.candidate().sessionId());
            redis.delete(List.of(sessionKey, nonceKey));
            return !Boolean.TRUE.equals(redis.hasKey(sessionKey))
                    && !Boolean.TRUE.equals(redis.hasKey(nonceKey));
        } catch (RuntimeException failure) {
            return false;
        }
    }

    private boolean isCurrent(PreparedSession session) {
        Instant now = clock.instant();
        return !session.candidate().generation().equals(identity.currentGeneration().orElse(null))
                || !now.isBefore(session.deadlines().idleExpiresAt())
                || !now.isBefore(session.deadlines().absoluteExpiresAt())
                || !now.isBefore(session.delivery().deliveryDeadline())
                || !now.isBefore(session.snapshot().customerStatus().validUntil());
    }

    private String sessionKey(PreparedSession session) {
        return sessions.forLookup(session.candidate().lookup().version(), session.candidate().lookup().digest());
    }

    private Map<String, String> sessionFields(PreparedSession session) {
        SessionActivationSnapshot snapshot = session.snapshot();
        SessionActivationContext context = snapshot.context();
        SessionKeyBindings keys = snapshot.keys();
        SessionSecurityVersions versions = snapshot.securityVersions();
        CustomerStatusFreshness customer = snapshot.customerStatus();
        Map<String, String> fields = new HashMap<>();
        fields.put("schemaVersion", "1");
        fields.put("state", "ACTIVE");
        fields.put("sessionId", session.candidate().sessionId().toString());
        fields.put("subjectId", context.subject().value().toString());
        fields.put("appId", context.appId());
        fields.put("audience", context.appId());
        fields.put("channel", "MOBILE");
        fields.put("scope", "[\"banking\"]");
        fields.put("deviceBindingId", context.bindingId().value().toString());
        fields.put("requestKeyJkt", keys.requestKey().base64Url());
        fields.put("requestPublicJwk", keys.requestPublicJwk());
        fields.put("generation", session.candidate().generation().toString());
        fields.put("customerSecurityVersion", Long.toString(versions.customerSecurityVersion()));
        fields.put("credentialSecurityVersion", Long.toString(versions.credentialSecurityVersion()));
        fields.put("deviceSecurityVersion", Long.toString(versions.deviceSecurityVersion()));
        fields.put("sessionVersion", "0");
        fields.put("customerStatusVersion", Long.toString(customer.customerStatusVersion()));
        fields.put("customerStatusValidUntilMs",
                Long.toString(customer.validUntil().toEpochMilli()));
        fields.put("createdAtMs", Long.toString(clock.millis()));
        fields.put("idleExpiresAtMs", Long.toString(session.deadlines().idleExpiresAt().toEpochMilli()));
        fields.put("absoluteExpiresAtMs", Long.toString(session.deadlines().absoluteExpiresAt().toEpochMilli()));
        fields.put("nonceFamilyId", session.candidate().sessionId().toString());
        SessionAssurance assurance = snapshot.assurance();
        fields.put("assurance", "{\"biometricEnforcement\":\"" + assurance.biometricEnforcement().code()
                + "\",\"devicePossession\":\"" + assurance.devicePossession().code()
                + "\",\"platformEvidence\":\"" + assurance.platformEvidence().code() + "\"}");
        return fields;
    }

    private Map<String, String> nonceFields(PreparedSession session) {
        String digest = digests.sha256(session.delivery().dpopNonce().getBytes(StandardCharsets.US_ASCII))
                .base64Url();
        Instant expiry = clock.instant().plus(nonceValidity);
        if (expiry.isAfter(session.deadlines().absoluteExpiresAt())) {
            expiry = session.deadlines().absoluteExpiresAt();
        }
        return Map.of("schemaVersion", "1", "familyId", session.candidate().sessionId().toString(),
                "requestKeyJkt", session.snapshot().keys().requestKey().base64Url(),
                "familyVersion", "0", "currentDigest", digest,
                "currentExpiresAtMs", Long.toString(expiry.toEpochMilli()),
                "previousDigest", "", "previousExpiresAtMs", "0",
                "familyDeadlineMs", Long.toString(session.deadlines().absoluteExpiresAt().toEpochMilli()));
    }
}
