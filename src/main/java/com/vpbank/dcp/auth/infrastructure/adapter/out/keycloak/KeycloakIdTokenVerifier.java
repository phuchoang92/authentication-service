package com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.constant.KeycloakEndpoints;
import com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.dto.JwksResponse;
import java.security.Key;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Checks the KC-signed ID token from Direct Grant: signature against the realm JWKS (RS256/ES256,
 * {@code use=sig}), {@code iss} = the realm issuer, {@code aud} contains our client, not expired.
 * The JWKS is fetched over the Keycloak {@link RestClient} and cached for a bounded time; an
 * unknown {@code kid} refreshes it once (key rotation).
 */
@RequiredArgsConstructor
public final class KeycloakIdTokenVerifier {
    static final Duration JWKS_TTL = Duration.ofMinutes(10);
    /** Nimbus defaults to 60 s; Keycloak and Auth share NTP, so a few seconds is enough. */
    static final int MAX_CLOCK_SKEW_SECONDS = 5;
    private static final String PARTNER = "Keycloak";
    private static final Set<JWSAlgorithm> ALGORITHMS = Set.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256);
    private static final Set<String> REQUIRED_CLAIMS = Set.of("sub", "exp", "iat");
    private static final boolean USE_CACHE = false;
    private static final boolean REFRESH = true;

    @NonNull private final RestClient restClient;
    @NonNull private final String realm;
    @NonNull private final String issuer;
    @NonNull private final String clientId;
    @NonNull private final Clock clock;

    private volatile JWKSet cachedJwks;
    private volatile Instant cachedJwksAt = Instant.EPOCH;

    /** The verified subject, or empty when the token is not acceptable. Throws when the JWKS cannot be fetched. */
    public Optional<String> verifiedSubject(String idToken) {
        try {
            SignedJWT jwt = SignedJWT.parse(idToken);
            if (!ALGORITHMS.contains(jwt.getHeader().getAlgorithm())) {
                return Optional.empty();
            }

            Optional<JWK> signingKey = signingKeyFor(jwt);
            if (signingKey.isEmpty()) {
                return Optional.empty();
            }
            JWSVerifier signatureVerifier =
                    new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), publicKey(signingKey.get()));
            if (!jwt.verify(signatureVerifier)) {
                return Optional.empty();
            }

            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            JWTClaimsSet exactClaims = new JWTClaimsSet.Builder().issuer(issuer).build();
            DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier =
                    new DefaultJWTClaimsVerifier<>(clientId, exactClaims, REQUIRED_CLAIMS) {
                        @Override
                        protected Date currentTime() {
                            return Date.from(clock.instant());
                        }
                    };
            claimsVerifier.setMaxClockSkew(MAX_CLOCK_SKEW_SECONDS);
            claimsVerifier.verify(claims, null);

            return Optional.ofNullable(claims.getSubject())
                    .filter(subject -> !subject.isBlank());
        } catch (ParseException | JOSEException | BadJWTException invalid) {
            return Optional.empty();
        }
    }

    /** The cached JWKS first; an unknown {@code kid} fetches the realm keys once more (rotation). */
    private Optional<JWK> signingKeyFor(SignedJWT jwt) {
        String keyId = jwt.getHeader().getKeyID();

        Optional<JWK> cachedKey = selectSigningKey(jwks(USE_CACHE), keyId);
        if (cachedKey.isPresent()) {
            return cachedKey;
        }
        return selectSigningKey(jwks(REFRESH), keyId);
    }

    private static Key publicKey(JWK jwk) throws JOSEException {
        if (jwk instanceof RSAKey rsaKey) {
            return rsaKey.toRSAPublicKey();
        }
        if (jwk instanceof ECKey ecKey) {
            return ecKey.toECPublicKey();
        }
        throw new JOSEException("Unsupported JWKS key type " + jwk.getKeyType());
    }

    /** A key with the token's {@code kid} (any key when the token names none) that is for signatures. */
    private static Optional<JWK> selectSigningKey(JWKSet jwks, String keyId) {
        for (JWK candidate : jwks.getKeys()) {
            boolean matchesKeyId = keyId == null || keyId.equals(candidate.getKeyID());
            boolean forSignatures = candidate.getKeyUse() == null || KeyUse.SIGNATURE.equals(candidate.getKeyUse());
            if (matchesKeyId && forSignatures) {
                return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }

    private JWKSet jwks(boolean refresh) {
        Instant now = clock.instant();

        JWKSet currentJwks = cachedJwks;
        boolean cacheFresh = currentJwks != null && Duration.between(cachedJwksAt, now).compareTo(JWKS_TTL) < 0;
        if (cacheFresh && !refresh) {
            return currentJwks;
        }

        JWKSet fetchedJwks;
        try {
            String jwksJson = restClient.get()
                    .uri(KeycloakEndpoints.JWKS, realm)
                    .retrieve()
                    .body(String.class);
            fetchedJwks = JWKSet.parse(new JwksResponse(jwksJson).json());
        } catch (RestClientException | ParseException | NullPointerException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }

        cachedJwks = fetchedJwks;
        cachedJwksAt = now;
        return fetchedJwks;
    }
}
