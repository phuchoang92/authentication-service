package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.auth.domain.model.ServiceId;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import lombok.NonNull;

/**
 * The client assertion an internal service presents to get a service token (slice 12), after RFC 7523: a
 * compact ES256 JWS, header {@code typ=service-client-assertion+jwt} naming the caller's pinned key, no embedded
 * or remote key ({@code jwk}, {@code jku}, {@code x5u}, {@code x5c}) and no {@code crit}; claims exactly
 * {@code iss, sub, aud, iat, exp, jti} with {@code iss} = {@code sub} = the service ID and
 * {@code aud=authentication-service}. The key is looked up by the service the assertion names, and the header's
 * {@code kid} must be that key's. The assertion lives at most 60 s; 5 s of clock skew is accepted. Anything
 * else is not an assertion. Replay is the caller's check.
 */
public final class ServiceClientAssertionVerifier {
    static final String AUDIENCE = "authentication-service";
    static final JOSEObjectType ASSERTION_TYPE = new JOSEObjectType("service-client-assertion+jwt");
    static final Set<String> CLAIMS = Set.of("iss", "sub", "aud", "iat", "exp", "jti");
    static final Duration MAX_LIFETIME = Duration.ofSeconds(60);
    static final Duration MAX_SKEW = Duration.ofSeconds(5);
    /** An assertion ID longer than this is not one a service issued. */
    private static final int MAX_ASSERTION_ID_LENGTH = 128;

    private final Map<ServiceId, ECKey> clientKeys;
    private final Clock clock;

    /** {@code clientKeys}: each service's pinned public P-256 key, carrying the key ID its headers will name. */
    public ServiceClientAssertionVerifier(@NonNull Map<ServiceId, ECKey> clientKeys, @NonNull Clock clock) {
        this.clientKeys = Map.copyOf(clientKeys);
        this.clock = clock;
        for (Map.Entry<ServiceId, ECKey> clientKey : this.clientKeys.entrySet()) {
            ECKey key = clientKey.getValue();
            if (key.isPrivate() || !Curve.P_256.equals(key.getCurve()) || key.getKeyID() == null) {
                throw new IllegalArgumentException("The key of " + clientKey.getKey() + " must be a public P-256 key with a key ID");
            }
        }
    }

    /** A genuine, current assertion: which service made it, and the ID and deadline the replay check needs. */
    public record VerifiedClientAssertion(@NonNull ServiceId clientService,
                                          @NonNull String assertionId,
                                          @NonNull Instant expiresAt) {
    }

    public Optional<VerifiedClientAssertion> verify(String compactAssertion) {
        try {
            SignedJWT assertionJws = SignedJWT.parse(compactAssertion);
            JWTClaimsSet claims = assertionJws.getJWTClaimsSet();
            boolean exactClaims = CLAIMS.equals(claims.getClaims().keySet())
                    && claims.getIssuer() != null
                    && claims.getIssuer().equals(claims.getSubject());
            if (!exactClaims) {
                return Optional.empty();
            }

            ServiceId clientService = new ServiceId(claims.getSubject());
            ECKey clientKey = clientKeys.get(clientService);
            if (clientKey == null || !hasThePinnedHeader(assertionJws.getHeader(), clientKey)) {
                return Optional.empty();
            }
            if (!assertionJws.verify(new ECDSAVerifier(clientKey.toECPublicKey()))) {
                return Optional.empty();
            }

            boolean currentAndForUs = List.of(AUDIENCE).equals(claims.getAudience())
                    && hasUsableAssertionId(claims.getJWTID())
                    && withinLifetime(claims);
            if (!currentAndForUs) {
                return Optional.empty();
            }
            Instant expiresAt = claims.getExpirationTime().toInstant();
            return Optional.of(new VerifiedClientAssertion(clientService, claims.getJWTID(), expiresAt));
        } catch (ParseException | JOSEException | IllegalArgumentException | ClassCastException | NullPointerException invalid) {
            // A claim present with a null or wrongly typed value lands here too.
            return Optional.empty();
        }
    }

    /** ES256 under the client service's key ID, the assertion type, and no key material or critical extension in the header. */
    private static boolean hasThePinnedHeader(JWSHeader header, ECKey clientKey) {
        boolean carriesAnotherKey = header.getJWK() != null
                || header.getJWKURL() != null
                || header.getX509CertURL() != null
                || header.getX509CertChain() != null;
        boolean hasCriticalExtension = header.getCriticalParams() != null && !header.getCriticalParams().isEmpty();
        return JWSAlgorithm.ES256.equals(header.getAlgorithm())
                && ASSERTION_TYPE.equals(header.getType())
                && clientKey.getKeyID().equals(header.getKeyID())
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
}
