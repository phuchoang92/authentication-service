package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.password.PasswordVerifierUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import org.junit.jupiter.api.Test;

class KeycloakIdTokenVerifierTest {

    private static final Instant NOW = Instant.parse("2026-10-11T12:00:00Z");
    private final ECKey signingKey;

    KeycloakIdTokenVerifierTest() throws Exception {
        signingKey = new ECKeyGenerator(Curve.P_256).keyID("kc-signing").generate();
    }

    @Test
    void signedIdentityForExactAudienceAndIssuerIsAccepted() throws Exception {
        var verifier = verifier(signingKey);
        assertEquals("customer-subject", verifier.verify(token(signingKey,
                "authentication-service", "https://kc.bank.test/realms/mobile-banking")).subject());
    }

    @Test
    void wrongAudienceAndForgedSigningKeyFailClosed() throws Exception {
        var verifier = verifier(signingKey);
        ECKey attacker = new ECKeyGenerator(Curve.P_256).keyID("kc-signing").generate();
        assertThrows(PasswordVerifierUnavailableException.class,
                () -> verifier.verify(token(signingKey, "other-client",
                        "https://kc.bank.test/realms/mobile-banking")));
        assertThrows(PasswordVerifierUnavailableException.class,
                () -> verifier.verify(token(attacker, "authentication-service",
                        "https://kc.bank.test/realms/mobile-banking")));
    }

    @Test
    void configuredClientIdMustMatchBothAudienceAndAuthorizedParty() throws Exception {
        var verifier = new KeycloakIdTokenVerifier("bank-auth-secret",
                "https://kc.bank.test/realms/mobile-banking", "kc-signing", signingKey.toPublicJWK(),
                new StrictJoseJson(), Clock.fixed(NOW, ZoneOffset.UTC));
        assertEquals("customer-subject", verifier.verify(token(signingKey, "bank-auth-secret",
                "https://kc.bank.test/realms/mobile-banking")).subject());
        assertThrows(PasswordVerifierUnavailableException.class,
                () -> verifier.verify(token(signingKey, "authentication-service",
                        "https://kc.bank.test/realms/mobile-banking")));
        assertThrows(PasswordVerifierUnavailableException.class,
                () -> verifier.verify(token(signingKey, "bank-auth-secret",
                        "https://kc.bank.test/realms/mobile-banking", "other-client")));
    }

    @Test
    void missingAuthorizedPartyFailsClosed() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://kc.bank.test/realms/mobile-banking")
                .subject("customer-subject")
                .audience("authentication-service")
                .issueTime(Date.from(NOW))
                .expirationTime(Date.from(NOW.plusSeconds(60)))
                .build();
        SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID("kc-signing").build(), claims);
        token.sign(new ECDSASigner(signingKey));

        assertThrows(PasswordVerifierUnavailableException.class,
                () -> verifier(signingKey).verify(token.serialize()));
    }

    private KeycloakIdTokenVerifier verifier(ECKey key) {
        return new KeycloakIdTokenVerifier("authentication-service", "https://kc.bank.test/realms/mobile-banking",
                "kc-signing", key.toPublicJWK(), new StrictJoseJson(),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private String token(ECKey key, String audience, String issuer) throws Exception {
        return token(key, audience, issuer, audience);
    }

    private String token(ECKey key, String audience, String issuer, String authorizedParty) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject("customer-subject")
                .audience(audience)
                .claim("azp", authorizedParty)
                .issueTime(Date.from(NOW))
                .expirationTime(Date.from(NOW.plusSeconds(60)))
                .build();
        SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID("kc-signing").build(), claims);
        token.sign(new ECDSASigner(key));
        return token.serialize();
    }
}
