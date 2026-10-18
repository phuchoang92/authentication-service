package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.port.out.credential.PasswordVerifierUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.testsupport.ContractVectors;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Stock Keycloak 26.7.1, isolated realm, test-only software client key. */
@Testcontainers
class KeycloakDirectGrantIT {

    private static final String REALM = "g2-direct-grant";
    private static final String ISSUER = "https://auth.bank.test/realms/" + REALM;
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5)).build();
    private static final JsonMapper JSON = JsonMapper.builder().build();

    @Container
    static final GenericContainer<?> KEYCLOAK = new GenericContainer<>(
            "quay.io/keycloak/keycloak:26.7.1")
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "test-admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "test-only-admin-password")
            .withCopyFileToContainer(MountableFile.forClasspathResource(
                    "keycloak/g2-direct-grant-realm.json"),
                    "/opt/keycloak/data/import/g2-direct-grant-realm.json")
            .withCommand("start-dev", "--import-realm", "--hostname=" + "https://auth.bank.test")
            .withExposedPorts(8080)
            .waitingFor(Wait.forHttp("/realms/" + REALM).forPort(8080)
                    .forStatusCode(200).withStartupTimeout(Duration.ofMinutes(3)));

    @Test
    void privateKeyJwtDirectGrantReturnsIdTokenOnlyForEnabledUserAndCorrectPassword()
            throws Exception {
        ECKey clientKey = clientKey();
        var assertions = new PrivateKeyJwtFactory("authentication-service", URI.create(ISSUER
                + "/protocol/openid-connect/token"), clientKey);
        var success = token("alice", "correct-password-test-only", assertions.issue(Clock.systemUTC().instant()));
        assertThat(success.statusCode()).as("OAuth error code: "
                + JSON.readTree(success.body()).path("error").asText())
                .isEqualTo(200);
        JsonNode reply = JSON.readTree(success.body());
        String idToken = reply.path("id_token").asText();
        assertThat(idToken).isNotBlank();

        SignedJWT signed = SignedJWT.parse(idToken);
        JWK signingKey = signingKey(signed.getHeader().getKeyID());
        var verifier = new KeycloakIdTokenVerifier("authentication-service", ISSUER, signed.getHeader().getKeyID(),
                signingKey, new StrictJoseJson(), Clock.systemUTC());
        var identity = verifier.verify(idToken);
        assertThat(identity.issuer()).isEqualTo(ISSUER);
        assertThat(identity.subject()).isNotBlank();
        assertThatThrownBy(() -> new KeycloakIdTokenVerifier("authentication-service", ISSUER, "wrong-kid",
                signingKey, new StrictJoseJson(), Clock.systemUTC()).verify(idToken))
                .isInstanceOf(PasswordVerifierUnavailableException.class);

        assertThat(token("alice", "wrong-password", assertions.issue(Clock.systemUTC().instant()))
                .statusCode()).isEqualTo(400);
        assertThat(token("disabled-user", "correct-password-test-only",
                assertions.issue(Clock.systemUTC().instant())).statusCode()).isEqualTo(400);
    }

    @Test
    void clientSecretDirectGrantReturnsIdentityForConfiguredClientAndRejectsWrongSecret() throws Exception {
        var success = secretToken("test-only-client-secret");
        assertThat(success.statusCode()).isEqualTo(200);
        String idToken = JSON.readTree(success.body()).path("id_token").asText();
        SignedJWT signed = SignedJWT.parse(idToken);
        var verifier = new KeycloakIdTokenVerifier("bank-auth-secret", ISSUER, signed.getHeader().getKeyID(),
                signingKey(signed.getHeader().getKeyID()), new StrictJoseJson(), Clock.systemUTC());
        assertThat(verifier.verify(idToken).subject()).isNotBlank();
        assertThat(signed.getJWTClaimsSet().getAudience()).containsExactly("bank-auth-secret");
        assertThat(signed.getJWTClaimsSet().getStringClaim("azp")).isEqualTo("bank-auth-secret");

        var rejected = secretToken("wrong-test-secret");
        assertThat(rejected.statusCode()).isIn(400, 401);
        assertThat(JSON.readTree(rejected.body()).path("error").asText()).isEqualTo("unauthorized_client");
    }

    private static HttpResponse<String> secretToken(String secret) throws Exception {
        return token("alice", "correct-password-test-only",
                Map.of("client_id", "bank-auth-secret", "client_secret", secret));
    }

    private static HttpResponse<String> token(String username, String password,
                                              String assertion) throws Exception {
        return token(username, password, Map.of("client_id", "authentication-service",
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion", assertion));
    }

    private static HttpResponse<String> token(String username, String password,
                                              Map<String, String> credentials) throws Exception {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("grant_type", "password");
        fields.putAll(credentials);
        fields.put("scope", "openid");
        fields.put("username", username);
        fields.put("password", password);
        String form = fields.entrySet().stream().map(entry -> encode(entry.getKey()) + "="
                + encode(entry.getValue())).collect(java.util.stream.Collectors.joining("&"));
        HttpRequest request = HttpRequest.newBuilder(endpoint("/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8)).build();
        return HTTP.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static JWK signingKey(String keyId) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(endpoint("/protocol/openid-connect/certs"))
                .timeout(Duration.ofSeconds(10)).GET().build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        return JWKSet.parse(response.body()).getKeys().stream()
                .filter(key -> keyId.equals(key.getKeyID()))
                .findFirst().orElseThrow();
    }

    private static URI endpoint(String suffix) {
        return URI.create("http://" + KEYCLOAK.getHost() + ":" + KEYCLOAK.getMappedPort(8080)
                + "/realms/" + REALM + suffix);
    }

    private static ECKey clientKey() throws Exception {
        JsonNode key = ContractVectors.load().path("keys").path("Kreq");
        return new ECKey.Builder(ECKey.parse(key.path("jwk").toString()))
                .d(Base64URL.encode(java.util.HexFormat.of().parseHex(
                        key.path("privateScalarHex").asText())))
                .keyID("test-client-key")
                .build();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
