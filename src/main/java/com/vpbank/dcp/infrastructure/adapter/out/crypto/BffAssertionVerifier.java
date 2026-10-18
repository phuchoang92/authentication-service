package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Verifies the JWT the BFF sends on the trusted-device API. The BFF has already authenticated
 * the App token; {@code sid} names that token's restricted session in Valkey.
 *
 * <p>Only the pinned key is accepted, never one the token carries. The claim set must match
 * exactly, so a JWT minted by the BFF for another purpose cannot be replayed here.
 */
public final class BffAssertionVerifier {
    static final String TYPE = "bff-assertion+jwt";
    static final String AUDIENCE = "authentication-service";
    private static final Set<String> CLAIMS =
            Set.of("iss", "aud", "sid", "channel", "deviceId", "iat", "exp", "jti");
    private static final Duration MAXIMUM_LIFETIME = Duration.ofSeconds(60);
    private static final Duration SKEW = Duration.ofSeconds(5);
    private static final Pattern SID = Pattern.compile("([A-Za-z0-9_-]{1,16}):([A-Za-z0-9_-]{43})");

    private final String issuer;
    private final String kid;
    private final ECKey pinnedPublicKey;
    private final StrictJoseJson strictJson;
    private final Sha256Digests digests;

    public BffAssertionVerifier(String issuer, String kid, ECKey pinnedPublicKey,
                                StrictJoseJson strictJson, Sha256Digests digests) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.kid = Objects.requireNonNull(kid, "kid");
        this.pinnedPublicKey = Objects.requireNonNull(pinnedPublicKey, "pinnedPublicKey");
        this.strictJson = Objects.requireNonNull(strictJson, "strictJson");
        this.digests = Objects.requireNonNull(digests, "digests");
        if (issuer.isBlank() || kid.isBlank() || pinnedPublicKey.isPrivate()
                || !Curve.P_256.equals(pinnedPublicKey.getCurve())) {
            throw new InvalidCryptographicInputException();
        }
    }

    public VerifiedBffAssertion verify(String compact, Instant now) {
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
        var sidParts = sid == null ? null : SID.matcher(sid);
        if (jti == null || jti.isBlank() || jti.length() > 128
                || sidParts == null || !sidParts.matches()
                || channel == null || channel.isBlank() || channel.length() > 64
                || deviceId == null || deviceId.length() < 16 || deviceId.length() > 300) {
            throw new InvalidCryptographicInputException();
        }
        return new VerifiedBffAssertion(
                new SessionTokenLookup(new LookupKeyVersion(sidParts.group(1)),
                        Digest32.fromBase64Url(sidParts.group(2))),
                channel, deviceId, digests.ofProofId(jti), expiresAt);
    }
}
