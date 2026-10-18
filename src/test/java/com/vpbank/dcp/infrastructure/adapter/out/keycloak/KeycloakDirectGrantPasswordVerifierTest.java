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
import com.vpbank.dcp.core.port.out.credential.PasswordVerifierUnavailableException;
import com.vpbank.dcp.core.port.out.credential.PasswordVerification;
import com.vpbank.dcp.core.port.out.credential.PasswordVerificationOutcome;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class KeycloakDirectGrantPasswordVerifierTest {

    @Test
    void invalidGrantIsGenericRejectionAndNoPasswordLeaksViaToString() throws Exception {
        DirectGrantTokenClient client = mock(DirectGrantTokenClient.class);
        ExternalHttpClient.Response<JsonNode, JsonNode> reply = errorReply("invalid_grant");
        when(client.requestTokens(any(), any())).thenReturn(reply);
        var verifier = new KeycloakDirectGrantPasswordVerifier(client, mock(KeycloakIdTokenVerifier.class));
        PasswordVerification credential = new PasswordVerification("alice", "sensitive-password");

        assertInstanceOf(PasswordVerificationOutcome.Rejected.class, verifier.verify(credential));
        assertEquals("PasswordVerification[redacted]", credential.toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"invalid_client", "unauthorized_client"})
    void otherClientErrorIsNotMistakenForWrongPassword(String error) throws Exception {
        DirectGrantTokenClient client = mock(DirectGrantTokenClient.class);
        ExternalHttpClient.Response<JsonNode, JsonNode> reply = errorReply(error);
        when(client.requestTokens(any(), any())).thenReturn(reply);
        var verifier = new KeycloakDirectGrantPasswordVerifier(client,
                mock(KeycloakIdTokenVerifier.class));

        assertThrows(PasswordVerifierUnavailableException.class,
                () -> verifier.verify(new PasswordVerification("alice", "private-password")));
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
        ExternalHttpClient.Response<JsonNode, JsonNode> reply = successReply(idToken.serialize());
        when(client.requestTokens(any(), any())).thenReturn(reply);
        var idVerifier = new KeycloakIdTokenVerifier("authentication-service", "https://kc.bank.test/realms/mobile-banking",
                "kc-id-v1", signingKey.toPublicJWK(), new StrictJoseJson(),
                Clock.fixed(now, ZoneOffset.UTC));
        var gateway = new KeycloakDirectGrantPasswordVerifier(client, idVerifier);

        var result = gateway.verify(new PasswordVerification("alice", "private-password"));

        assertEquals("immutable-sub", ((PasswordVerificationOutcome.Verified) result)
                .identity().subject());
        ExternalHttpClient.Response<JsonNode, JsonNode> missingIdentity = successReply(null);
        assertThrows(PasswordVerifierUnavailableException.class, () -> {
            when(client.requestTokens(any(), any())).thenReturn(missingIdentity);
            gateway.verify(new PasswordVerification("alice", "private-password"));
        });
    }

    @SuppressWarnings("unchecked")
    private ExternalHttpClient.Response<JsonNode, JsonNode> errorReply(String code) throws Exception {
        ExternalHttpClient.Response<JsonNode, JsonNode> response = mock(ExternalHttpClient.Response.class);
        when(response.status()).thenReturn(400);
        when(response.errorBody()).thenReturn(JsonMapper.builder().build()
                .readTree("{\"error\":\"" + code + "\"}"));
        return response;
    }

    @SuppressWarnings("unchecked")
    private ExternalHttpClient.Response<JsonNode, JsonNode> successReply(String identityToken) throws Exception {
        ExternalHttpClient.Response<JsonNode, JsonNode> response = mock(ExternalHttpClient.Response.class);
        when(response.status()).thenReturn(200);
        when(response.isSuccess()).thenReturn(true);
        String body = identityToken == null ? "{}" : "{\"id_token\":\"" + identityToken + "\"}";
        when(response.successBody()).thenReturn(JsonMapper.builder().build().readTree(body));
        return response;
    }
}
