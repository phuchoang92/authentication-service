package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import com.vpbank.dcp.infrastructure.adapter.in.web.ForwardedPublicRequest;
import com.vpbank.dcp.infrastructure.config.properties.PasswordFlowProperties;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.json.JsonMapper;

class PasswordLoginRequestMapperTest {
    private final PasswordLoginRequestMapper mapper = new PasswordLoginRequestMapper(
            new ExternalUriPolicy("https://api.bank.example"),
            new PasswordFlowProperties("k1", "unused", "v1", 30_000, 120_000, 300_000),
            JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build(),
            Clock.fixed(Instant.parse("2026-10-12T00:00:00Z"), ZoneOffset.UTC));

    @Test
    void derivesTheOnlyPasswordCommandFromExactCapturedBytes() {
        var mapped = mapper.map(forward(body("alice", "test-password")));
        assertThat(mapped.operation().username()).isEqualTo("alice");
        assertThat(mapped.credential().password()).isEqualTo("test-password");
        assertThat(mapped.toString()).doesNotContain("test-password");
    }

    @Test
    void rejectsDuplicatePasswordFieldAndUnexpectedField() {
        assertThatThrownBy(() -> mapper.map(forward(body("alice", "first")
                .replace("\"password\":\"first\"",
                        "\"password\":\"first\",\"password\":\"second\""))))
                .isInstanceOf(InvalidPasswordLoginRequestException.class);
        assertThatThrownBy(() -> mapper.map(forward(body("alice", "first")
                .replace("\"platform\":\"ANDROID\"",
                        "\"platform\":\"ANDROID\",\"unknown\":true"))))
                .isInstanceOf(InvalidPasswordLoginRequestException.class);
    }

    @Test
    void deserializesBffEnvelopeWithoutCopyingThePasswordIntoAnotherField() {
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(
                body("alice", "test-password").getBytes(StandardCharsets.UTF_8));
        String forwarded = "{\"original\":{\"method\":\"POST\"," +
                "\"publicUri\":\"https://api.bank.example/api/v1/authentications/password\"," +
                "\"dpopProof\":\"proof\",\"bodyBase64\":\"" + encoded + "\"," +
                "\"idempotencyKey\":\"44444444-4444-4444-8444-444444444444\"}}";
        var parsed = JsonMapper.builder().build().readValue(forwarded,
                PasswordLoginRequest.class);

        assertThat(mapper.map(parsed).credential().password()).isEqualTo("test-password");
        assertThat(parsed.toString()).doesNotContain("test-password");
    }

    private PasswordLoginRequest forward(String body) {
        return new PasswordLoginRequest(new ForwardedPublicRequest(
                "POST", "https://api.bank.example/api/v1/authentications/password",
                "proof", null, Base64.getUrlEncoder().withoutPadding().encodeToString(
                        body.getBytes(StandardCharsets.UTF_8)),
                "44444444-4444-4444-8444-444444444444"));
    }

    private String body(String username, String password) {
        String coordinate = "A".repeat(43);
        return "{" +
                "\"appId\":\"neo-mobile\"," +
                "\"platform\":\"ANDROID\"," +
                "\"installationId\":\"install-c02bdd64-1234-4567-8901\"," +
                "\"username\":\"" + username + "\"," +
                "\"password\":\"" + password + "\"," +
                "\"responseKey\":{\"version\":1,\"algorithm\":\"ECDH-ES+A256GCM\"," +
                "\"format\":\"JWK\",\"publicJwk\":{\"kty\":\"EC\"," +
                "\"crv\":\"P-256\",\"x\":\"" + coordinate + "\"," +
                "\"y\":\"" + coordinate + "\"}}," +
                "\"requestKeyProof\":\"key-proof\"}";
    }
}
