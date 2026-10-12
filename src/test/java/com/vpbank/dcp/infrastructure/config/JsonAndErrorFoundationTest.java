package com.vpbank.dcp.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import com.vpbank.dcp.infrastructure.adapter.in.web.InvalidExternalUriException;
import com.vpbank.dcp.infrastructure.adapter.in.web.error.ApiErrorHandler;
import com.vpbank.dcp.core.port.out.security.DpopExpectation;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.InvalidCryptographicInputException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.TokenLookupHasher;
import com.vpbank.dcp.core.port.out.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.infrastructure.config.properties.KeycloakContextTrustProperties;
import java.net.URI;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import tools.jackson.databind.json.JsonMapper;

class JsonAndErrorFoundationTest {

    record RequestBody(String operation) {
    }

    @Test
    void configuredHttpJsonRejectsDuplicateAndUnknownMembers() {
        var builder = JsonMapper.builder();
        new JsonConfiguration().strictJson().customize(builder);
        JsonMapper mapper = builder.build();
        assertThatThrownBy(() -> mapper.readTree("{\"operation\":1,\"operation\":2}"))
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> mapper.readValue("{\"operation\":\"login\",\"secret\":\"x\"}",
                RequestBody.class)).isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> mapper.readTree("{\"operation\":\"login\"}true"))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void joseJsonRejectsDuplicateHeaderBeforeSignatureVerification() {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"alg\":\"ES256\",\"alg\":\"none\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString("{}".getBytes());
        assertThatThrownBy(() -> new StrictJoseJson().checkCompactJws(header + "." + payload + ".AA"))
                .isInstanceOf(InvalidCryptographicInputException.class);
        assertThatThrownBy(() -> new StrictJoseJson().checkJson("[]"))
                .isInstanceOf(InvalidCryptographicInputException.class);
        assertThatThrownBy(() -> new StrictJoseJson().checkJson("{\"x\":\"\uD800\"}"))
                .isInstanceOf(InvalidCryptographicInputException.class);
    }

    @Test
    void publicErrorsNeverExposeInternalCauses() {
        var response = new ApiErrorHandler().authorityUnavailable(
                new ReplayAuthorityUnavailableException(new IllegalStateException("internal-secret")));
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(response.getBody().toString()).doesNotContain("internal-secret");
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
    }

    @Test
    void secretValueObjectsDoNotRenderSecrets() {
        var token = "k1." + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
        var expectation = DpopExpectation.forToken("GET", URI.create("https://api.bank.test/a"),
                new com.vpbank.dcp.core.domain.security.RequestKeyThumbprint(
                        Digest32.fromBytes(new byte[32])), "nonce-value", token, Instant.now());
        assertThat(expectation.toString()).doesNotContain(token, "nonce-value");
        assertThat(Digest32.fromBytes(new byte[32]).toString()).doesNotContain("AAAAAAAA");
        try (var hasher = new TokenLookupHasher(new LookupKeyVersion("k1"), new byte[32])) {
            assertThat(hasher.toString()).doesNotContain(token);
        }
    }

    @Test
    void externalOriginIsConfiguredAndPercentAmbiguityIsRejected() {
        var policy = new ExternalUriPolicy("https://api.bank.test");
        assertThat(policy.forPath("/api/v1/authentications").toASCIIString())
                .isEqualTo("https://api.bank.test/api/v1/authentications");
        assertThatThrownBy(() -> policy.forPath("/api/%2e%2e/admin"))
                .isInstanceOf(InvalidExternalUriException.class);
        assertThatThrownBy(() -> policy.forPath("/api/.."))
                .isInstanceOf(InvalidExternalUriException.class);
        assertThatThrownBy(() -> new ExternalUriPolicy("http://api.bank.test"))
                .isInstanceOf(InvalidExternalUriException.class);
    }

    @Test
    void malformedPinnedKeycloakTrustCannotBecomeAWorkingVerifier() {
        var trust = new KeycloakContextTrustProperties(
                "https://keycloak.bank.test/realms/mobile", "kc-context-1", "{}");
        assertThatThrownBy(() -> new CryptoConfiguration().signedContextVerifier(
                trust, new StrictJoseJson()))
                .isInstanceOf(InvalidContextTrustConfigurationException.class);
    }
}
