package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.out.session.BankingSessionAdmissionStore;
import com.vpbank.dcp.core.port.out.session.BankingSessionLookup;
import com.vpbank.dcp.core.port.out.session.SessionAdmissionResult;
import com.vpbank.dcp.core.port.out.session.SessionAuthorityUnavailableException;
import com.vpbank.dcp.core.port.out.session.VerifiedSessionProof;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.InvalidCryptographicInputException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.ProofDigests;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.TokenLookupHasher;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.CustomerFeedKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GenerationKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GuardKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.NonceKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.SessionKeys;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

/** Uses one atomic script for the proof replay marker, guards and eligible touch. */
public final class RedisBankingSessionAdmission implements BankingSessionAdmissionStore {
    private final StringRedisTemplate redis;
    private final RedisServerIdentity identity;
    private final TokenLookupHasher lookupHasher;
    private final LookupKeyVersion lookupVersion;
    private final GenerationKeys generations;
    private final CustomerFeedKeys feeds;
    private final GuardKeys guards;
    private final SessionKeys sessions = new SessionKeys();
    private final NonceKeys nonces;
    private final ReplayKeys replay;
    private final DefaultRedisScript<String> script;
    private final String feedSource;
    private final Duration nonceValidity;
    private final Duration nonceOverlap;
    private final SecureRandom random;
    private final ProofDigests digests = new ProofDigests();

    public RedisBankingSessionAdmission(StringRedisTemplate redis, RedisServerIdentity identity,
                                        TokenLookupHasher lookupHasher,
                                        LookupKeyVersion lookupVersion,
                                        AuthorityScope scope, DefaultRedisScript<String> script,
                                        String feedSource, Duration nonceValidity,
                                        Duration nonceOverlap, SecureRandom random) {
        this.redis = Objects.requireNonNull(redis);
        this.identity = Objects.requireNonNull(identity);
        this.lookupHasher = Objects.requireNonNull(lookupHasher);
        this.lookupVersion = Objects.requireNonNull(lookupVersion);
        this.generations = new GenerationKeys(scope);
        this.feeds = new CustomerFeedKeys(scope);
        this.guards = new GuardKeys(scope);
        this.nonces = new NonceKeys(scope);
        this.replay = new ReplayKeys(scope);
        this.script = Objects.requireNonNull(script);
        this.feedSource = Objects.requireNonNull(feedSource);
        this.nonceValidity = Objects.requireNonNull(nonceValidity);
        this.nonceOverlap = Objects.requireNonNull(nonceOverlap);
        this.random = Objects.requireNonNull(random);
        if (nonceOverlap.isNegative() || nonceOverlap.compareTo(nonceValidity) > 0
                || nonceValidity.toMillis() > 120000) {
            throw new InvalidAuthorityRedisConfigurationException();
        }
    }

    @Override
    public Optional<BankingSessionLookup> lookup(String exactToken) {
        Digest32 digest;
        try {
            digest = lookupHasher.digest(exactToken);
        } catch (InvalidCryptographicInputException invalid) {
            return Optional.empty();
        }
        try {
            Map<Object, Object> values = redis.opsForHash().entries(
                    sessions.forLookup(lookupVersion, digest));
            if (values.isEmpty()) {
                return Optional.empty();
            }
            if (values.size() != 23 || !"1".equals(values.get("schemaVersion"))
                    || !"ACTIVE".equals(values.get("state"))) {
                return Optional.empty();
            }
            return Optional.of(new BankingSessionLookup(lookupVersion, digest,
                    UUID.fromString(text(values, "generation")),
                    UUID.fromString(text(values, "sessionId")),
                    UUID.fromString(text(values, "subjectId")),
                    UUID.fromString(text(values, "deviceBindingId")),
                    text(values, "appId"),
                    new RequestKeyThumbprint(Digest32.fromBase64Url(
                            text(values, "requestKeyJkt")))));
        } catch (RuntimeException failure) {
            throw new SessionAuthorityUnavailableException(failure);
        }
    }

    @Override
    public SessionAdmissionResult admit(BankingSessionLookup lookup, VerifiedSessionProof proof,
                                        boolean eligibleActivity) {
        Objects.requireNonNull(lookup);
        Objects.requireNonNull(proof);
        String runId = identity.currentRunId();
        if (runId == null) {
            return new SessionAdmissionResult.AuthorityClosed();
        }
        byte[] nonceBytes = new byte[32];
        random.nextBytes(nonceBytes);
        String nextNonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
        String nextDigest = digests.sha256(nextNonce.getBytes(StandardCharsets.US_ASCII))
                .base64Url();
        List<String> keys = List.of(generations.control(), feeds.forSource(feedSource),
                guards.forSubject(lookup.subjectId()), guards.forDevice(lookup.bindingId()),
                guards.forSession(lookup.sessionId()),
                sessions.forLookup(lookup.lookupVersion(), lookup.lookupDigest()),
                nonces.forFamily(lookup.sessionId()),
                replay.forDpop(lookup.requestKey(), proof.proofId()));
        try {
            String result = redis.execute(script, keys, runId, lookup.generation().toString(),
                    lookup.sessionId().toString(), lookup.subjectId().toString(),
                    lookup.bindingId().toString(), lookup.requestKey().digest().base64Url(),
                    lookup.appId(), feedSource, "ADMIT", proof.nonceDigest().base64Url(),
                    eligibleActivity ? "1" : "0", nextDigest,
                    Long.toString(nonceValidity.toMillis()),
                    Long.toString(nonceOverlap.toMillis()));
            if ("NONCE_REQUIRED".equals(result)) {
                return new SessionAdmissionResult.NonceRequired(nextNonce);
            }
            if (result != null && result.startsWith("ADMITTED:")) {
                String[] deadlines = result.split(":", -1);
                if (deadlines.length == 3) {
                    return new SessionAdmissionResult.Admitted(new SessionDeadlines(
                            Instant.ofEpochMilli(Long.parseLong(deadlines[1])),
                            Instant.ofEpochMilli(Long.parseLong(deadlines[2]))));
                }
            }
            return "CLOSED".equals(result) ? new SessionAdmissionResult.AuthorityClosed()
                    : new SessionAdmissionResult.Denied();
        } catch (RuntimeException failure) {
            throw new SessionAuthorityUnavailableException(failure);
        }
    }

    private String text(Map<Object, Object> values, String field) {
        Object value = values.get(field);
        if (!(value instanceof String result)) {
            throw new InvalidAuthorityRedisConfigurationException();
        }
        return result;
    }
}
