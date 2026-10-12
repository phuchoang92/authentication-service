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
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;

import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * Verifies JOSE and server-pinned HTTP bindings; replay reservation remains a separate atomic step.
 */
public final class DpopProofVerifier {

    private static final Set<String> ALLOWED_CLAIMS = Set.of(
            "jti", "htm", "htu", "iat", "nonce", "ath");

    private final Sha256Digests digests;
    private final StrictJoseJson strictJson;

    public DpopProofVerifier(Sha256Digests digests, StrictJoseJson strictJson) {
        this.digests = Objects.requireNonNull(digests, "digests");
        this.strictJson = Objects.requireNonNull(strictJson, "strictJson");
    }

    public VerifiedDpopProof verify(String compact, DpopExpectation expectation) {
        Objects.requireNonNull(compact, "compact");
        Objects.requireNonNull(expectation, "expectation");
        if (compact.length() > 8192 || compact.split("\\.", -1).length != 3) {
            throw new InvalidCryptographicInputException();
        }
        strictJson.checkCompactJws(compact);
        try {
            SignedJWT proof = SignedJWT.parse(compact);
            ECKey publicKey = checkedPublicKey(proof.getHeader());
            if (!proof.verify(new ECDSAVerifier(publicKey))) {
                throw new InvalidCryptographicInputException();
            }
            RequestKeyThumbprint requestKey = new RequestKeyThumbprint(
                    Digest32.fromBase64Url(publicKey.computeThumbprint().toString()));
            if (expectation.requestKey() != null && !expectation.requestKey().equals(requestKey)) {
                throw new InvalidCryptographicInputException();
            }

            JWTClaimsSet claims = proof.getJWTClaimsSet();
            if (!ALLOWED_CLAIMS.containsAll(claims.getClaims().keySet())
                    || !expectation.method().equals(claims.getStringClaim("htm"))
                    || !canonicalExternalUri(expectation.externalUri())
                    .equals(canonicalExternalUri(URI.create(claims.getStringClaim("htu"))))) {
                throw new InvalidCryptographicInputException();
            }
            Instant issuedAt = Objects.requireNonNull(claims.getIssueTime(), "iat").toInstant();
            long ageSeconds = expectation.now().getEpochSecond() - issuedAt.getEpochSecond();
            if (ageSeconds > 30 || ageSeconds < -5) {
                throw new InvalidCryptographicInputException();
            }
            String proofId = claims.getStringClaim("jti");
            if (proofId == null || proofId.isBlank()) {
                throw new InvalidCryptographicInputException();
            }
            if (!Objects.equals(expectation.nonce(), claims.getStringClaim("nonce"))) {
                throw new InvalidCryptographicInputException();
            }
            String actualTokenHash = claims.getStringClaim("ath");
            if (expectation.exactToken() == null) {
                if (actualTokenHash != null) {
                    throw new InvalidCryptographicInputException();
                }
            } else if (!digests.ofToken(expectation.exactToken()).base64Url().equals(actualTokenHash)) {
                throw new InvalidCryptographicInputException();
            }
            return new VerifiedDpopProof(requestKey, digests.ofProofId(proofId), issuedAt);
        } catch (JOSEException | ParseException failure) {
            throw new InvalidCryptographicInputException(failure);
        } catch (NullPointerException | IllegalArgumentException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }

    private ECKey checkedPublicKey(JWSHeader header) {
        if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())
                || header.getType() == null
                || !"dpop+jwt".equals(header.getType().toString())
                || !(header.getJWK() instanceof ECKey key)
                || !Curve.P_256.equals(key.getCurve())
                || key.isPrivate()
                || header.getJWKURL() != null
                || header.getX509CertURL() != null
                || (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty())) {
            throw new InvalidCryptographicInputException();
        }
        return (ECKey) header.getJWK();
    }

    private String canonicalExternalUri(URI uri) {
        if (uri == null || !"https".equalsIgnoreCase(uri.getScheme())
                || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getRawQuery() != null || uri.getRawFragment() != null
                || uri.getRawPath() == null || !uri.getRawPath().startsWith("/")
                || uri.getRawPath().contains("%")
                || uri.getRawPath().length() > 2048
                || hasDotSegment(uri.getRawPath())) {
            throw new InvalidCryptographicInputException();
        }
        int port = uri.getPort() == 443 ? -1 : uri.getPort();
        String host = uri.getHost().toLowerCase();
        if (host.contains(":")) {
            host = "[" + host + "]";
        }
        return "https://" + host + (port < 0 ? "" : ":" + port) + uri.getRawPath();
    }

    private boolean hasDotSegment(String path) {
        for (String segment : path.split("/", -1)) {
            if (".".equals(segment) || "..".equals(segment)) {
                return true;
            }
        }
        return false;
    }
}
