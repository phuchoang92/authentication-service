package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * The BFF assertion of DD 20 §6a, extended for slice 11: a compact ES256 JWS from the pinned BFF key, header
 * {@code typ=bff-assertion+jwt} naming that key, no embedded or remote key ({@code jwk}, {@code jku},
 * {@code x5u}, {@code x5c}) and no {@code crit}; claims exactly {@code iss, aud, sub, sid, channel, deviceId,
 * sessionKind, iat, exp, jti}. {@code sub} is the customer number and {@code sessionKind} the kind of session the
 * BFF admitted (slice 11 adds both; Auth no longer reads the session to learn them). The assertion lives at most
 * 60 s; 5 s of clock skew is accepted. Anything else is not an assertion. Replay is the caller's check.
 */
public final class BffAssertionVerifier {
    static final String AUDIENCE = "authentication-service";
    static final JOSEObjectType ASSERTION_TYPE = new JOSEObjectType("bff-assertion+jwt");
    static final Set<String> CLAIMS = Set.of("iss", "aud", "sub", "sid", "channel", "deviceId", "sessionKind",
            "iat", "exp", "jti");
    static final Duration MAX_LIFETIME = Duration.ofSeconds(60);
    static final Duration MAX_SKEW = Duration.ofSeconds(5);
    /** An assertion ID longer than this is not one the BFF issued. */
    private static final int MAX_ASSERTION_ID_LENGTH = 128;
    private static final Set<SessionStatus> ADMITTED_KINDS = Set.of(SessionStatus.ACTIVE, SessionStatus.NEED_TRUSTED_DEVICE);

    private final ECKey bffAssertionKey;
    private final String issuer;
    private final Clock clock;

    /** {@code bffAssertionKey} is the pinned public P-256 key; it must carry the key ID the header names. */
    public BffAssertionVerifier(ECKey bffAssertionKey, String issuer, Clock clock) {
        this.bffAssertionKey = Objects.requireNonNull(bffAssertionKey, "bffAssertionKey");
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (bffAssertionKey.isPrivate() || bffAssertionKey.getKeyID() == null) {
            throw new IllegalArgumentException("The BFF assertion key must be a public key with a key ID");
        }
    }

    /** A genuine, current assertion: who the BFF admitted, and the ID and deadline the replay check needs. */
    public record VerifiedAssertion(AdmittedSession admittedSession, String assertionId, Instant expiresAt) {
        public VerifiedAssertion {
            Objects.requireNonNull(admittedSession, "admittedSession");
            Objects.requireNonNull(assertionId, "assertionId");
            Objects.requireNonNull(expiresAt, "expiresAt");
        }
    }

    public Optional<VerifiedAssertion> verify(String compactAssertion) {
        try {
            SignedJWT assertionJws = SignedJWT.parse(compactAssertion);
            if (!hasThePinnedHeader(assertionJws.getHeader())) {
                return Optional.empty();
            }
            if (!assertionJws.verify(new ECDSAVerifier(bffAssertionKey.toECPublicKey()))) {
                return Optional.empty();
            }

            JWTClaimsSet claims = assertionJws.getJWTClaimsSet();
            boolean currentAndForUs = CLAIMS.equals(claims.getClaims().keySet())
                    && issuer.equals(claims.getIssuer())
                    && List.of(AUDIENCE).equals(claims.getAudience())
                    && hasUsableAssertionId(claims.getJWTID())
                    && withinLifetime(claims);
            if (!currentAndForUs) {
                return Optional.empty();
            }

            AdmittedSession admittedSession = admittedSessionOf(claims);
            Instant expiresAt = claims.getExpirationTime().toInstant();
            return Optional.of(new VerifiedAssertion(admittedSession, claims.getJWTID(), expiresAt));
        } catch (ParseException | JOSEException | IllegalArgumentException | ClassCastException | NullPointerException invalid) {
            // A claim present with a null or wrongly typed value lands here too.
            return Optional.empty();
        }
    }

    /** ES256 under the pinned key ID, the assertion type, and no key material or critical extension in the header. */
    private boolean hasThePinnedHeader(JWSHeader header) {
        boolean carriesAnotherKey = header.getJWK() != null
                || header.getJWKURL() != null
                || header.getX509CertURL() != null
                || header.getX509CertChain() != null;
        boolean hasCriticalExtension = header.getCriticalParams() != null && !header.getCriticalParams().isEmpty();
        return JWSAlgorithm.ES256.equals(header.getAlgorithm())
                && ASSERTION_TYPE.equals(header.getType())
                && bffAssertionKey.getKeyID().equals(header.getKeyID())
                && !carriesAnotherKey
                && !hasCriticalExtension;
    }

    private static boolean hasUsableAssertionId(String assertionId) {
        return assertionId != null && !assertionId.isBlank() && assertionId.length() <= MAX_ASSERTION_ID_LENGTH;
    }

    /** Issued already, not expired, and never valid for more than 60 s. */
    private boolean withinLifetime(JWTClaimsSet claims) {
        if (claims.getIssueTime() == null || claims.getExpirationTime() == null) {
            return false;
        }
        Instant issuedAt = claims.getIssueTime().toInstant();
        Instant expiresAt = claims.getExpirationTime().toInstant();
        Instant now = clock.instant();

        boolean lifetimeIsShort = expiresAt.isAfter(issuedAt)
                && Duration.between(issuedAt, expiresAt).compareTo(MAX_LIFETIME) <= 0;
        boolean alreadyIssued = issuedAt.minus(MAX_SKEW).isBefore(now);
        boolean notExpired = expiresAt.plus(MAX_SKEW).isAfter(now);
        return lifetimeIsShort && alreadyIssued && notExpired;
    }

    /** Each claim must be a valid value of its type; a bad value means the assertion is not one Auth accepts. */
    private static AdmittedSession admittedSessionOf(JWTClaimsSet claims) throws ParseException {
        SessionId sessionId = new SessionId(UUID.fromString(claims.getStringClaim("sid")));
        CustomerId customerId = new CustomerId(claims.getStringClaim("sub"));
        Channel channel = Channel.valueOf(claims.getStringClaim("channel"));
        DeviceId deviceId = new DeviceId(claims.getStringClaim("deviceId"));
        SessionStatus sessionKind = SessionStatus.valueOf(claims.getStringClaim("sessionKind"));
        if (!ADMITTED_KINDS.contains(sessionKind)) {
            throw new IllegalArgumentException("Not an admitted session kind");
        }
        return new AdmittedSession(sessionId, customerId, channel, deviceId, sessionKind);
    }
}
