package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.credential.PasswordVerifierUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/** Validates a pinned Keycloak ID token; a private subnet or HTTP 200 is not identity proof. */
public final class KeycloakIdTokenVerifier {

    private final String clientId;

    private final String issuer;
    private final String keyId;
    private final JWSAlgorithm algorithm;
    private final JWSVerifier signatureVerifier;
    private final StrictJoseJson strictJson;
    private final Clock clock;

    public KeycloakIdTokenVerifier(String clientId, String issuer, String keyId, JWK publicKey,
                                   StrictJoseJson strictJson, Clock clock) {
        if (clientId == null || clientId.isBlank()) {
            throw new InvalidKeycloakClientConfigurationException();
        }
        this.clientId = clientId;
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.keyId = Objects.requireNonNull(keyId, "keyId");
        this.strictJson = Objects.requireNonNull(strictJson, "strictJson");
        this.clock = Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(publicKey, "publicKey");
        if (!issuer.startsWith("https://") || keyId.isBlank() || publicKey.isPrivate()) {
            throw new InvalidKeycloakClientConfigurationException();
        }
        try {
            if (publicKey instanceof RSAKey rsa) {
                algorithm = JWSAlgorithm.RS256;
                signatureVerifier = new RSASSAVerifier(rsa);
            } else if (publicKey instanceof ECKey ec
                    && com.nimbusds.jose.jwk.Curve.P_256.equals(ec.getCurve())) {
                algorithm = JWSAlgorithm.ES256;
                signatureVerifier = new ECDSAVerifier(ec);
            } else {
                throw new InvalidKeycloakClientConfigurationException();
            }
        } catch (JOSEException failure) {
            throw new InvalidKeycloakClientConfigurationException(failure);
        }
    }

    public VerifiedProviderIdentity verify(String compact) {
        Objects.requireNonNull(compact, "compact");
        try {
            strictJson.checkCompactJws(compact);
            SignedJWT token = SignedJWT.parse(compact);
            if (!algorithm.equals(token.getHeader().getAlgorithm())
                    || !keyId.equals(token.getHeader().getKeyID())
                    || token.getHeader().getJWK() != null
                    || token.getHeader().getJWKURL() != null
                    || token.getHeader().getX509CertURL() != null
                    || token.getHeader().getCriticalParams() != null
                    || !token.verify(signatureVerifier)) {
                throw new PasswordVerifierUnavailableException();
            }
            JWTClaimsSet claims = token.getJWTClaimsSet();
            Instant now = clock.instant();
            if (!issuer.equals(claims.getIssuer())
                    || claims.getSubject() == null || claims.getSubject().isBlank()
                    || claims.getAudience().size() != 1
                    || !clientId.equals(claims.getAudience().getFirst())
                    || !clientId.equals(claims.getStringClaim("azp"))
                    || claims.getIssueTime() == null || claims.getExpirationTime() == null
                    || claims.getIssueTime().toInstant().isAfter(now.plusSeconds(5))
                    || claims.getIssueTime().toInstant().isBefore(now.minusSeconds(60))
                    || !claims.getExpirationTime().toInstant().isAfter(now)
                    || (claims.getNotBeforeTime() != null
                            && claims.getNotBeforeTime().toInstant().isAfter(now.plusSeconds(5)))) {
                throw new PasswordVerifierUnavailableException();
            }
            return new VerifiedProviderIdentity(issuer, claims.getSubject());
        } catch (ParseException | JOSEException | IllegalArgumentException failure) {
            throw new PasswordVerifierUnavailableException(failure);
        }
    }
}
