package com.vpbank.dcp.auth.adapter.out.keycloak;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.vpbank.dcp.auth.adapter.out.keycloak.dto.JwksResponse;
import com.vpbank.dcp.auth.application.port.out.PartnerUnavailableException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.security.Key;
import java.util.Optional;
import java.util.Set;

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
    private static final Set<JWSAlgorithm> ALGORITHMS = Set.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256);

    @NonNull private final RestClient client;
    @NonNull private final String realm;
    @NonNull private final String issuer;
    @NonNull private final String clientId;
    @NonNull private final Clock clock;
    private volatile JWKSet cached;
    private volatile Instant cachedAt = Instant.EPOCH;

    /** The verified subject, or empty when the token is not acceptable. Throws when the JWKS cannot be fetched. */
    public Optional<String> verifiedSubject(String idToken) {
        try {
            SignedJWT jwt = SignedJWT.parse(idToken);
            if (!ALGORITHMS.contains(jwt.getHeader().getAlgorithm())) {
                return Optional.empty();
            }
            JWK key = keyFor(jwt);
            if (key == null || !jwt.verify(new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), publicKey(key)))) {
                return Optional.empty();
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            DefaultJWTClaimsVerifier<SecurityContext> verifier = new DefaultJWTClaimsVerifier<>(clientId,
                    new JWTClaimsSet.Builder().issuer(issuer).build(), Set.of("sub", "exp", "iat")) {
                @Override
                protected Date currentTime() {
                    return Date.from(clock.instant());
                }
            };
            verifier.setMaxClockSkew(MAX_CLOCK_SKEW_SECONDS);
            verifier.verify(claims, null);
            return Optional.ofNullable(claims.getSubject()).filter(sub -> !sub.isBlank());
        } catch (ParseException | JOSEException | BadJWTException invalid) {
            return Optional.empty();
        }
    }

    private JWK keyFor(SignedJWT jwt) {
        String kid = jwt.getHeader().getKeyID();
        JWK key = select(jwks(false), kid);
        return key != null ? key : select(jwks(true), kid);
    }

    private static Key publicKey(JWK key) throws JOSEException {
        if (key instanceof RSAKey rsa) {
            return rsa.toRSAPublicKey();
        }
        if (key instanceof ECKey ec) {
            return ec.toECPublicKey();
        }
        throw new JOSEException("Unsupported JWKS key type " + key.getKeyType());
    }

    private static JWK select(JWKSet set, String kid) {
        return set.getKeys().stream()
                .filter(k -> kid == null || kid.equals(k.getKeyID()))
                .filter(k -> k.getKeyUse() == null || KeyUse.SIGNATURE.equals(k.getKeyUse()))
                .findFirst().orElse(null);
    }

    private JWKSet jwks(boolean refresh) {
        Instant now = clock.instant();
        JWKSet set = cached;
        if (set != null && !refresh && Duration.between(cachedAt, now).compareTo(JWKS_TTL) < 0) {
            return set;
        }
        try {
            String json = client.get().uri("/realms/{realm}/protocol/openid-connect/certs", realm)
                    .retrieve().body(String.class);
            set = JWKSet.parse(new JwksResponse(json).json());
        } catch (RestClientException | ParseException | NullPointerException failure) {
            throw new PartnerUnavailableException("Keycloak", failure);
        }
        cached = set;
        cachedAt = now;
        return set;
    }
}
