package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.session.TrustedDeviceCaller;
import com.vpbank.dcp.core.replay.AssertionReplay;
import com.vpbank.dcp.core.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.core.trusteddevice.BffCallerAssertions;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Verifies the JWT the BFF sends on the trusted-device API. The BFF has already authenticated
 * the App token; {@code sid} is that token's session ID (draft doc 21 §2).
 *
 * <p>Only the pinned key is accepted, never one the token carries. The claim set must match
 * exactly, so a JWT minted by the BFF for another purpose cannot be replayed here.
 */
public final class BffAssertionVerifier implements BffCallerAssertions {
    static final String TYPE = "bff-assertion+jwt";
    static final String AUDIENCE = "authentication-service";
    private static final Set<String> CLAIMS =
            Set.of("iss", "aud", "sid", "channel", "deviceId", "iat", "exp", "jti");
    private static final Duration MAXIMUM_LIFETIME = Duration.ofSeconds(60);
    private static final Duration SKEW = Duration.ofSeconds(5);
    /** Canonical lowercase UUID only, so one session has exactly one {@code sid} spelling. */
    private static final Pattern SID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private final String issuer;
    private final String kid;
    private final ECKey pinnedPublicKey;
    private final StrictJoseJson strictJson;
    private final Sha256Digests digests;
    private final AssertionReplay replay;

    public BffAssertionVerifier(String issuer, String kid, ECKey pinnedPublicKey,
                                StrictJoseJson strictJson, Sha256Digests digests,
                                AssertionReplay replay) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.kid = Objects.requireNonNull(kid, "kid");
        this.pinnedPublicKey = Objects.requireNonNull(pinnedPublicKey, "pinnedPublicKey");
        this.strictJson = Objects.requireNonNull(strictJson, "strictJson");
        this.digests = Objects.requireNonNull(digests, "digests");
        this.replay = Objects.requireNonNull(replay, "replay");
        if (issuer.isBlank() || kid.isBlank() || pinnedPublicKey.isPrivate()
                || !Curve.P_256.equals(pinnedPublicKey.getCurve())) {
            throw new InvalidCryptographicInputException();
        }
    }

    @Override
    public Optional<TrustedDeviceCaller> accept(String compactAssertion, Instant now) {
        VerifiedBffAssertion verified;
        try {
            verified = verify(compactAssertion, now);
        } catch (InvalidCryptographicInputException invalid) {
            return Optional.empty();
        }
        return switch (replay.reserve(verified.assertionIdDigest(), verified.expiresAt())) {
            case RESERVED -> Optional.of(new TrustedDeviceCaller(verified.sessionId(),
                    verified.channel(), verified.deviceId()));
            case REPLAYED -> Optional.empty();
            case AUTHORITY_CLOSED -> throw new ReplayAuthorityUnavailableException();
        };
    }

    /** Throws {@link InvalidCryptographicInputException} for anything not exactly an assertion. */
    VerifiedBffAssertion verify(String compact, Instant now) {
        Objects.requireNonNull(compact, "compact");
        Objects.requireNonNull(now, "now");
        strictJson.checkCompactJws(compact);
        try {
            SignedJWT signed = SignedJWT.parse(compact);
            JWSHeader header = signed.getHeader();
            if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())
                    || header.getType() == null || !TYPE.equals(header.getType().toString())
                    || !kid.equals(header.getKeyID())
                    || header.getJWK() != null || header.getJWKURL() != null
                    || header.getX509CertURL() != null || header.getX509CertChain() != null
                    || (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty())
                    || !signed.verify(new ECDSAVerifier(pinnedPublicKey))) {
                throw new InvalidCryptographicInputException();
            }
            return claims(signed.getJWTClaimsSet(), now);
        } catch (ParseException | JOSEException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }

    private VerifiedBffAssertion claims(JWTClaimsSet claims, Instant now) throws ParseException {
        if (!CLAIMS.equals(claims.getClaims().keySet())
                || !issuer.equals(claims.getIssuer())
                || claims.getAudience().size() != 1 || !AUDIENCE.equals(claims.getAudience().getFirst())
                || claims.getIssueTime() == null || claims.getExpirationTime() == null) {
            throw new InvalidCryptographicInputException();
        }
        Instant issuedAt = claims.getIssueTime().toInstant();
        Instant expiresAt = claims.getExpirationTime().toInstant();
        if (now.isBefore(issuedAt.minus(SKEW)) || !now.isBefore(expiresAt)
                || !expiresAt.isAfter(issuedAt)
                || expiresAt.isAfter(issuedAt.plus(MAXIMUM_LIFETIME))) {
            throw new InvalidCryptographicInputException();
        }
        String jti = claims.getJWTID();
        String sid = claims.getStringClaim("sid");
        String channel = claims.getStringClaim("channel");
        String deviceId = claims.getStringClaim("deviceId");
        if (jti == null || jti.isBlank() || jti.length() > 128
                || sid == null || !SID.matcher(sid).matches()
                || channel == null || channel.isBlank() || channel.length() > 64
                || deviceId == null || deviceId.length() < 16 || deviceId.length() > 300) {
            throw new InvalidCryptographicInputException();
        }
        return new VerifiedBffAssertion(
                UUID.fromString(sid), channel, deviceId, digests.ofProofId(jti), expiresAt);
    }
}
