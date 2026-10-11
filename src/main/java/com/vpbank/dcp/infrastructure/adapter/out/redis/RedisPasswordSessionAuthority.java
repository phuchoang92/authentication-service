package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.port.out.session.PasswordSessionAuthority;
import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;
import com.vpbank.dcp.core.port.out.session.SessionApplyResult;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.ProofDigests;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingControlCodec;
import com.vpbank.dcp.infrastructure.adapter.out.redis.codec.ServingState;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ApplyReceiptKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.CustomerFeedKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GenerationKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GuardKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.NonceKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

/** The candidate is never online without an exact fenced apply and live delivery check. */
public final class RedisPasswordSessionAuthority implements PasswordSessionAuthority {
    private final StringRedisTemplate redis;
    private final RedisServerIdentity identity;
    private final GenerationKeys generations;
    private final CustomerFeedKeys feeds;
    private final GuardKeys guards;
    private final SessionKeys sessions;
    private final NonceKeys nonces;
    private final ApplyReceiptKeys receipts;
    private final DefaultRedisScript<String> applyScript;
    private final DefaultRedisScript<String> deliverScript;
    private final String feedSource;
    private final Duration nonceValidity;
    private final Clock clock;
    private final ProofDigests digests = new ProofDigests();

    public RedisPasswordSessionAuthority(StringRedisTemplate redis,
                                         RedisServerIdentity identity, AuthorityScope scope,
                                         DefaultRedisScript<String> applyScript,
                                         DefaultRedisScript<String> deliverScript,
                                         String feedSource, Duration nonceValidity, Clock clock) {
        this.redis = Objects.requireNonNull(redis);
        this.identity = Objects.requireNonNull(identity);
        this.generations = new GenerationKeys(scope);
        this.feeds = new CustomerFeedKeys(scope);
        this.guards = new GuardKeys(scope);
        this.sessions = new SessionKeys();
        this.nonces = new NonceKeys(scope);
        this.receipts = new ApplyReceiptKeys(scope);
        this.applyScript = Objects.requireNonNull(applyScript);
        this.deliverScript = Objects.requireNonNull(deliverScript);
        this.feeds.forSource(feedSource);
        this.feedSource = feedSource;
        this.nonceValidity = Objects.requireNonNull(nonceValidity);
        this.clock = Objects.requireNonNull(clock);
        if (nonceValidity.toMillis() < 1000 || nonceValidity.toMillis() > 120000) {
            throw new InvalidAuthorityRedisConfigurationException();
        }
    }

    @Override
    public Optional<UUID> currentGeneration() {
        try {
            String runId = identity.currentRunId();
            if (runId == null) {
                return Optional.empty();
            }
            var control = new ServingControlCodec().decode(redis.opsForHash().entries(
                    generations.control()));
            if (control.state() != ServingState.READY || !runId.equals(control.redisRunId())
                    || !clock.instant().isBefore(control.leaseUntil())) {
                return Optional.empty();
            }
            return Optional.of(control.generation());
        } catch (RuntimeException failure) {
            return Optional.empty();
        }
    }

    @Override
    public SessionApplyResult apply(PreparedPasswordSession session) {
        Objects.requireNonNull(session);
        String runId = identity.currentRunId();
        if (runId == null || runId.isBlank()) {
            return SessionApplyResult.AUTHORITY_CLOSED;
        }
        var facts = session.facts();
        List<String> keys = List.of(generations.control(), feeds.forSource(feedSource),
                guards.forSubject(facts.subjectId()), guards.forDevice(facts.bindingId()),
                guards.forSession(session.sessionId()),
                sessions.forLookup(session.lookupVersion(), session.lookupDigest()),
                nonces.forFamily(session.sessionId()), receipts.forIntent(session.intentId()));
        String assurance = "{\"biometricEnforcement\":\"NOT_APPLICABLE\","
                + "\"devicePossession\":\"MFA_KEY_POSSESSION\","
                + "\"platformEvidence\":\"" + facts.platformAssurance() + "\"}";
        String nonceDigest = digests.sha256(session.dpopNonce().getBytes(StandardCharsets.US_ASCII))
                .base64Url();
        try {
            String result = redis.execute(applyScript, keys, runId,
                    session.generation().toString(), facts.operationId().toString(),
                    session.intentId().toString(), session.candidateDigest().base64Url(),
                    session.sessionId().toString(), facts.subjectId().toString(),
                    facts.bindingId().toString(), facts.appId(), facts.requestPublicJwk(),
                    facts.requestKey().base64Url(), nonceDigest,
                    Long.toString(facts.customerSecurityVersion()),
                    Long.toString(facts.credentialSecurityVersion()),
                    Long.toString(facts.deviceSecurityVersion()),
                    Long.toString(facts.customerStatusVersion()),
                    Long.toString(facts.customerStatusValidUntil().toEpochMilli()),
                    Long.toString(session.deadlines().idleExpiresAt().toEpochMilli()),
                    Long.toString(session.deadlines().absoluteExpiresAt().toEpochMilli()),
                    Long.toString(session.deliveryDeadline().toEpochMilli()),
                    session.lookupDigest().base64Url(), assurance,
                    Long.toString(nonceValidity.toMillis()), feedSource);
            return switch (result) {
                case "APPLIED" -> SessionApplyResult.APPLIED;
                case "ALREADY_APPLIED" -> SessionApplyResult.ALREADY_APPLIED;
                case "DENIED" -> SessionApplyResult.DENIED;
                default -> SessionApplyResult.AUTHORITY_CLOSED;
            };
        } catch (RuntimeException failure) {
            return SessionApplyResult.AUTHORITY_CLOSED;
        }
    }

    @Override
    public boolean deliverable(PreparedPasswordSession session) {
        Objects.requireNonNull(session);
        String runId = identity.currentRunId();
        if (runId == null || runId.isBlank()) {
            return false;
        }
        var facts = session.facts();
        List<String> keys = List.of(generations.control(), feeds.forSource(feedSource),
                guards.forSubject(facts.subjectId()), guards.forDevice(facts.bindingId()),
                guards.forSession(session.sessionId()),
                sessions.forLookup(session.lookupVersion(), session.lookupDigest()),
                nonces.forFamily(session.sessionId()));
        try {
            return "DELIVERABLE".equals(redis.execute(deliverScript, keys, runId,
                    session.generation().toString(), session.sessionId().toString(),
                    facts.subjectId().toString(), facts.bindingId().toString(),
                    facts.requestKey().base64Url(), facts.appId(), feedSource));
        } catch (RuntimeException failure) {
            return false;
        }
    }
}
