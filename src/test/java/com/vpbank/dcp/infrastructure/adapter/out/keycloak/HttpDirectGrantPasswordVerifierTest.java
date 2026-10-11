package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.port.out.keycloak.KeycloakVerificationUnavailableException;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerificationOutcome;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class HttpDirectGrantPasswordVerifierTest {

    @Test
    void invalidGrantIsGenericRejectionAndNoPasswordLeaksViaToString() {
        DirectGrantTokenClient client = mock(DirectGrantTokenClient.class);
        when(client.verify(any())).thenReturn(new DirectGrantTokenClient.Response(
                400, "{\"error\":\"invalid_grant\",\"error_description\":\"ignored\"}"));
        var verifier = new HttpDirectGrantPasswordVerifier(client, mock(KeycloakIdTokenVerifier.class),
                new StrictJoseJson(), JsonMapper.builder().build());
        PasswordVerification credential = new PasswordVerification("alice", "sensitive-password");

        assertInstanceOf(PasswordVerificationOutcome.Rejected.class, verifier.verify(credential));
        assertEquals("PasswordVerification[redacted]", credential.toString());
    }

    @Test
    void verifiedIdTokenYieldsOnlyProviderIdentity() throws Exception {
        Instant now = Instant.parse("2026-10-11T12:00:00Z");
        var signingKey = new ECKeyGenerator(Curve.P_256).keyID("kc-id-v1").generate();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://kc.bank.test/realms/mobile-banking")
                .subject("immutable-sub")
                .audience("authentication-service")
                .claim("azp", "authentication-service")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(30)))
                .build();
        SignedJWT idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID("kc-id-v1").build(), claims);
        idToken.sign(new ECDSASigner(signingKey));
        DirectGrantTokenClient client = mock(DirectGrantTokenClient.class);
        when(client.verify(any())).thenReturn(new DirectGrantTokenClient.Response(200,
                "{\"access_token\":\"must-never-escape\",\"refresh_token\":\"also-secret\","
                        + "\"id_token\":\"" + idToken.serialize() + "\"}"));
        var idVerifier = new KeycloakIdTokenVerifier("https://kc.bank.test/realms/mobile-banking",
                "kc-id-v1", signingKey.toPublicJWK(), new StrictJoseJson(),
                Clock.fixed(now, ZoneOffset.UTC));
        var gateway = new HttpDirectGrantPasswordVerifier(client, idVerifier,
                new StrictJoseJson(), JsonMapper.builder().build());

        var result = gateway.verify(new PasswordVerification("alice", "private-password"));

        assertEquals("immutable-sub", ((PasswordVerificationOutcome.Verified) result)
                .identity().subject());
        assertThrows(KeycloakVerificationUnavailableException.class, () -> {
            when(client.verify(any())).thenReturn(new DirectGrantTokenClient.Response(200,
                    "{\"access_token\":\"must-never-escape\"}"));
            gateway.verify(new PasswordVerification("alice", "private-password"));
        });
    }
}
