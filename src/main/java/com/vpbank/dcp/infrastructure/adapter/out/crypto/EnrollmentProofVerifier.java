package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/** Verifies the typed enrollment JWS using the request key pinned to the transaction. */
public final class EnrollmentProofVerifier {

    private static final Set<String> EXPECTED_CLAIMS = Set.of(
            "v", "enrollmentId", "purpose", "appId", "ath", "requestKeyJkt",
            "inputDigest", "newKeyJkt", "commandDigest", "jti", "iat", "exp");

    private final StrictJoseJson strictJson;
    private final ProofDigests digests;

    public EnrollmentProofVerifier(StrictJoseJson strictJson, ProofDigests digests) {
        this.strictJson = Objects.requireNonNull(strictJson, "strictJson");
        this.digests = Objects.requireNonNull(digests, "digests");
    }

    public VerifiedEnrollmentProof verify(
            String compact, ECKey publicRequestKey, ExpectedEnrollmentProof expected) {
        Objects.requireNonNull(publicRequestKey, "publicRequestKey");
        Objects.requireNonNull(expected, "expected");
        strictJson.checkCompactJws(compact);
        try {
            SignedJWT signed = SignedJWT.parse(compact);
            var header = signed.getHeader();
            if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())
                    || header.getType() == null
                    || !"bank-enrollment+jwt".equals(header.getType().toString())
                    || !expected.requestKey().digest().base64Url().equals(header.getKeyID())
                    || header.getJWK() != null || header.getJWKURL() != null
                    || header.getX509CertURL() != null
                    || (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty())
                    || publicRequestKey.isPrivate()
                    || !Curve.P_256.equals(publicRequestKey.getCurve())
                    || !expected.requestKey().digest().base64Url()
                            .equals(publicRequestKey.computeThumbprint().toString())
                    || !signed.verify(new ECDSAVerifier(publicRequestKey))) {
                throw new InvalidCryptographicInputException();
            }
            JWTClaimsSet claims = signed.getJWTClaimsSet();
            Instant issued = Objects.requireNonNull(claims.getIssueTime(), "iat").toInstant();
            Instant expiry = Objects.requireNonNull(claims.getExpirationTime(), "exp").toInstant();
            if (!EXPECTED_CLAIMS.equals(claims.getClaims().keySet())
                    || !Long.valueOf(1).equals(claims.getLongClaim("v"))
                    || !expected.enrollmentId().toString().equals(claims.getStringClaim("enrollmentId"))
                    || !expected.purpose().equals(claims.getStringClaim("purpose"))
                    || !expected.appId().equals(claims.getStringClaim("appId"))
                    || !expected.tokenHash().base64Url().equals(claims.getStringClaim("ath"))
                    || !expected.requestKey().digest().base64Url().equals(claims.getStringClaim("requestKeyJkt"))
                    || !expected.signingInputHash().base64Url().equals(claims.getStringClaim("inputDigest"))
                    || !expected.newKeyThumbprint().base64Url().equals(claims.getStringClaim("newKeyJkt"))
                    || !expected.commandHash().base64Url().equals(claims.getStringClaim("commandDigest"))
                    || claims.getJWTID() == null || claims.getJWTID().isBlank()
                    || expected.now().isBefore(issued.minusSeconds(5))
                    || !expected.now().isBefore(expiry)
                    || expiry.isAfter(issued.plusSeconds(120))) {
                throw new InvalidCryptographicInputException();
            }
            return new VerifiedEnrollmentProof(digests.ofProofId(claims.getJWTID()));
        } catch (JOSEException | ParseException | NullPointerException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }
}
