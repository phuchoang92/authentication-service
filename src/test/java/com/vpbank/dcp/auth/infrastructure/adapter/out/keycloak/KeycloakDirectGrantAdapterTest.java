package com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort.VerificationResult;
import com.vpbank.dcp.auth.domain.model.Password;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.net.SocketTimeoutException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class KeycloakDirectGrantAdapterTest {
    private static final String BASE = "https://kc.test";
    private static final String ISSUER = BASE + "/realms/test";
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00Z");
    private static final RSAKey KEY = generate("kc-key-1");
    private static final RSAKey OTHER = generate("other");

    private final RestClient.Builder builder = RestClient.builder().baseUrl(BASE);
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final RestClient client = builder.build();
    private final KeycloakDirectGrantAdapter keycloak = new KeycloakDirectGrantAdapter(client, "test", ISSUER,
            "authentication-service", "secret",
            new KeycloakIdTokenVerifier(client, "test", ISSUER, "authentication-service", Clock.fixed(NOW, ZoneOffset.UTC)));

    @Test
    void aValidPasswordYieldsTheVerifiedSubjectFromTheSignedIdToken() throws Exception {
        expectTokenCall().andRespond(withSuccess("{\"access_token\":\"x\",\"id_token\":\"" + idToken(KEY, ISSUER,
                "authentication-service", "sub-1", NOW.plusSeconds(60)) + "\"}", MediaType.APPLICATION_JSON));
        expectJwks();

        assertThat(keycloak.verify(new UserName("alice"), new Password("Secret123".toCharArray())))
                .isEqualTo(new VerificationResult.Verified(ISSUER, "sub-1"));
        server.verify();
    }

    @Test
    void invalidGrantIsRejectedWithoutTouchingTheJwks() {
        expectTokenCall().andRespond(withStatus(HttpStatus.UNAUTHORIZED).contentType(MediaType.APPLICATION_JSON)
                .body("{\"error\":\"invalid_grant\",\"error_description\":\"Invalid user credentials\"}"));

        assertThat(keycloak.verify(new UserName("alice"), new Password("wrong".toCharArray())))
                .isInstanceOf(VerificationResult.Rejected.class);
        server.verify();
    }

    @Test
    void aTokenSignedByAnotherKeyForAnotherAudienceOrExpiredIsUnavailable() throws Exception {
        for (String bad : List.of(
                idToken(OTHER, ISSUER, "authentication-service", "sub-1", NOW.plusSeconds(60)),
                idToken(KEY, ISSUER, "someone-else", "sub-1", NOW.plusSeconds(60)),
                idToken(KEY, "https://evil/realms/test", "authentication-service", "sub-1", NOW.plusSeconds(60)),
                idToken(KEY, ISSUER, "authentication-service", "sub-1", NOW.minusSeconds(KeycloakIdTokenVerifier.MAX_CLOCK_SKEW_SECONDS + 1)))) {
            server.reset();
            expectTokenCall().andRespond(withSuccess("{\"id_token\":\"" + bad + "\"}", MediaType.APPLICATION_JSON));
            expectJwks();
            expectJwks(); // unknown kid or failed verification refreshes once
            assertThatThrownBy(() -> keycloak.verify(new UserName("alice"), new Password("x".toCharArray())))
                    .isInstanceOf(PartnerUnavailableException.class);
        }
    }

    @Test
    void serverErrorsTimeoutsAndMissingIdTokenAreUnavailable() {
        expectTokenCall().andRespond(withStatus(HttpStatus.BAD_GATEWAY));
        assertThatThrownBy(() -> keycloak.verify(new UserName("alice"), new Password("x".toCharArray())))
                .isInstanceOf(PartnerUnavailableException.class);

        server.reset();
        expectTokenCall().andRespond(withException(new SocketTimeoutException("slow")));
        assertThatThrownBy(() -> keycloak.verify(new UserName("alice"), new Password("x".toCharArray())))
                .isInstanceOf(PartnerUnavailableException.class);

        server.reset();
        expectTokenCall().andRespond(withSuccess("{\"access_token\":\"only\"}", MediaType.APPLICATION_JSON));
        assertThatThrownBy(() -> keycloak.verify(new UserName("alice"), new Password("x".toCharArray())))
                .isInstanceOf(PartnerUnavailableException.class);
    }

    private org.springframework.test.web.client.ResponseActions expectTokenCall() {
        return server.expect(requestTo(BASE + "/realms/test/protocol/openid-connect/token"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().formDataContains(Map.of("grant_type", "password", "client_id", "authentication-service",
                        "client_secret", "secret", "username", "alice", "scope", "openid")));
    }

    private void expectJwks() {
        server.expect(requestTo(BASE + "/realms/test/protocol/openid-connect/certs"))
                .andRespond(withSuccess(new JWKSet(KEY.toPublicJWK()).toString(), MediaType.APPLICATION_JSON));
    }

    private static String idToken(RSAKey key, String issuer, String audience, String subject, Instant exp) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().issuer(issuer).audience(audience).subject(subject)
                        .issueTime(Date.from(NOW.minusSeconds(1))).expirationTime(Date.from(exp)).build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static RSAKey generate(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).keyUse(KeyUse.SIGNATURE).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
