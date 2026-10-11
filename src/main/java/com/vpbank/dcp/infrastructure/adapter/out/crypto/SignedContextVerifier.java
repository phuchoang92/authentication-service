package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Instant;
import java.util.Objects;

/** Verifies a configured KC signing authority, never a key supplied by the response. */
public final class SignedContextVerifier {

    private final String issuer;
    private final String kid;
    private final ECKey pinnedPublicKey;
    private final StrictJoseJson strictJson;

    public SignedContextVerifier(
            String issuer, String kid, ECKey pinnedPublicKey, StrictJoseJson strictJson) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.kid = Objects.requireNonNull(kid, "kid");
        this.pinnedPublicKey = Objects.requireNonNull(pinnedPublicKey, "pinnedPublicKey");
        this.strictJson = Objects.requireNonNull(strictJson, "strictJson");
        if (issuer.isBlank() || kid.isBlank() || pinnedPublicKey.isPrivate()
                || !Curve.P_256.equals(pinnedPublicKey.getCurve())) {
            throw new InvalidCryptographicInputException();
        }
    }

    public JWTClaimsSet verify(
            String compact, String expectedAudience, String expectedPurpose, Instant now) {
        Objects.requireNonNull(expectedAudience, "expectedAudience");
        Objects.requireNonNull(expectedPurpose, "expectedPurpose");
        Objects.requireNonNull(now, "now");
        strictJson.checkCompactJws(compact);
        try {
            SignedJWT signed = SignedJWT.parse(compact);
            JWSHeader header = signed.getHeader();
            if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())
                    || header.getType() == null
                    || !"bank-credential-context+jwt".equals(header.getType().toString())
                    || !kid.equals(header.getKeyID())
                    || header.getJWK() != null
                    || header.getJWKURL() != null
                    || header.getX509CertURL() != null
                    || (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty())
                    || !signed.verify(new ECDSAVerifier(pinnedPublicKey))) {
                throw new InvalidCryptographicInputException();
            }
            JWTClaimsSet claims = signed.getJWTClaimsSet();
            if (!issuer.equals(claims.getIssuer())
                    || claims.getAudience().size() != 1
                    || !expectedAudience.equals(claims.getAudience().getFirst())
                    || !expectedPurpose.equals(claims.getStringClaim("purpose"))
                    || claims.getJWTID() == null
                    || claims.getIssueTime() == null
                    || claims.getExpirationTime() == null
                    || now.isBefore(claims.getIssueTime().toInstant().minusSeconds(5))
                    || !now.isBefore(claims.getExpirationTime().toInstant())
                    || claims.getExpirationTime().toInstant()
                            .isAfter(claims.getIssueTime().toInstant().plusSeconds(120))) {
                throw new InvalidCryptographicInputException();
            }
            return claims;
        } catch (ParseException | JOSEException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }
}
