package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import com.vpbank.dcp.infrastructure.adapter.in.web.BoundedJsonBodyAdvice;
import org.springframework.http.converter.HttpMessageNotReadableException;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginRequest;
import com.vpbank.dcp.infrastructure.adapter.in.web.security.DpopProofFilter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import com.vpbank.dcp.core.port.in.password.PasswordLoginUseCase;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import com.vpbank.dcp.core.port.out.security.DpopProofDecoder;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import com.vpbank.dcp.infrastructure.adapter.in.web.security.SecurityErrorResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.error.ApiErrorHandler;
import com.vpbank.dcp.infrastructure.config.JsonConfiguration;
import com.vpbank.dcp.infrastructure.config.properties.PasswordFlowProperties;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import tools.jackson.databind.json.JsonMapper;

class PasswordLoginRequestMapperTest {
    private static final String PATH = "/internal/v1/authentications/password";
    private static final String OPERATION = "44444444-4444-4444-8444-444444444444";
    private static final String DPOP = "p".repeat(64);
    private final PasswordLoginUseCase passwords = mock(PasswordLoginUseCase.class);
    private final LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
    private final VerifiedDpopProof dpop = mock(VerifiedDpopProof.class);
    private JsonMapper json;
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        JsonMapper.Builder builder = JsonMapper.builder();
        try (var context = new AnnotationConfigApplicationContext(JsonConfiguration.class)) {
            context.getBean(JsonMapperBuilderCustomizer.class).customize(builder);
        }
        json = builder.build();
        Clock clock = Clock.fixed(Instant.parse("2026-10-12T00:00:00Z"), ZoneOffset.UTC);
        var mapper = new PasswordLoginRequestMapper(new PasswordFlowProperties("v1", 120_000, 300_000), json, clock);
        DpopProofDecoder decoder = mock(DpopProofDecoder.class);
        when(decoder.verify(any(), any())).thenReturn(dpop);
        validator.afterPropertiesSet();
        mvc = MockMvcBuilders.standaloneSetup(new PasswordLoginController(mapper, passwords,
                        new PasswordLoginResponseMapper(clock)))
                .setMessageConverters(new JacksonJsonHttpMessageConverter(json))
                .setValidator(validator)
                .setControllerAdvice(new BoundedJsonBodyAdvice(), new ApiErrorHandler())
                .addFilter(new DpopProofFilter(decoder, new ExternalUriPolicy("https://api.bank.example"),
                        clock, new SecurityErrorResponse(json))).build();
        when(passwords.login(any())).thenReturn(new PasswordLoginResult.Rejected());
    }

    @AfterEach
    void closeValidator() {
        validator.close();
    }

    @Test
    void mapsDirectBodyAndSeparateHeadersWithoutTransformingCredentials() throws Exception {
        String password = " p@ss\"\\\nViệt ";
        String body = validBody().replace("\"test-password\"", json.writeValueAsString(password));
        mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON)
                        .header("DPoP", DPOP).header("Idempotency-Key", OPERATION)
                        .header("X-Forwarded-Host", "attacker.example").content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REQUEST_REJECTED"))
                .andExpect(jsonPath("$.nextAction").value("START_NEW_LOGIN"));

        var command = ArgumentCaptor.forClass(PasswordLoginCommand.class);
        verify(passwords).login(command.capture());
        assertThat(command.getValue().credential().password()).isEqualTo(password);
        assertThat(command.getValue().credential().username()).isEqualTo("alice");
        assertThat(command.getValue().operation().operationId().toString()).isEqualTo(OPERATION);
        assertThat(command.getValue().proofs().dpop()).isSameAs(dpop);
        assertThat(json.readTree(command.getValue().proofs().responsePublicJwk()))
                .isEqualTo(json.readTree(body).path("tokenEncryptionKey").path("publicJwk"));
        assertThat(command.getValue().credentialDeadline()).isEqualTo(Instant.parse("2026-10-12T00:02:00Z"));
        assertThat(command.getValue().toString()).doesNotContain(password);
        var parsed = json.readValue(body, PasswordLoginRequest.class);
        assertThat(json.readTree(json.writeValueAsString(parsed)).has("tokenEncryptionKey")).isTrue();
        assertThat(json.readTree(json.writeValueAsString(parsed)).has("responseKey")).isFalse();
        assertThat(parsed.toString()).doesNotContain(password);
        assertThat(PasswordLoginRequest.builder().password(password).toString()).doesNotContain(password);
        assertThat(json.writeValueAsString(parsed)).doesNotContain(password, "password");
    }

    @Test
    void acceptsServerIssuedBindingIdWithoutAssumingUuidSyntax() throws Exception {
        String opaqueBindingId = "dev_" + "A".repeat(32);
        String body = validBody().replace("\"username\":",
                "\"deviceBindingId\":\"" + opaqueBindingId + "\",\"username\":");

        mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON)
                        .header("DPoP", DPOP).header("Idempotency-Key", OPERATION).content(body))
                .andExpect(status().isUnauthorized());

        var command = ArgumentCaptor.forClass(PasswordLoginCommand.class);
        verify(passwords).login(command.capture());
        assertThat(command.getValue().operation().claimedBindingId()).isEqualTo(opaqueBindingId);
    }

    @ParameterizedTest
    @MethodSource("invalidBodies")
    void rejectsInvalidJsonAndBodyContractBeforeUseCase(String body) throws Exception {
        var result = mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON)
                        .header("DPoP", DPOP).header("Idempotency-Key", OPERATION).content(body))
                .andExpect(status().isBadRequest()).andReturn();
        assertThat(result.getResponse().getContentAsString()).doesNotContain("test-password");
        verifyNoInteractions(passwords);
    }

    static Stream<String> invalidBodies() {
        String body = validBody();
        return Stream.of(
                body.replace("\"tokenEncryptionKey\":", "\"responseKey\":"),
                body.replace("\"password\":\"test-password\"", "\"password\":\"first\",\"password\":\"second\""),
                body.replace("\"platform\":\"ANDROID\"", "\"platform\":\"ANDROID\",\"unknown\":true"),
                body + " {}",
                body.replace("\"neo-mobile\"", "\"other-app\""),
                body.replace("\"ANDROID\"", "\"UNKNOWN\""),
                body.replace("\"alice\"", "\" \""),
                body.replace("\"test-password\"", "null"),
                body.replace("\"test-password\"", "123"),
                body.replace("\"test-password\"", "\"\""),
                body.replace("test-password", "x".repeat(1025)),
                body.replace("\"password\":\"test-password\",", ""),
                body.replace("\"installationId\":\"install-c02bdd64-1234-4567-8901\"", "\"installationId\":\"short\""),
                body.replace("\"version\":1", "\"version\":0"),
                body.replace("\"version\":1", "\"version\":\"1\""),
                body.replace("\"version\":1", "\"version\":1.5"),
                body.replace("ECDH-ES+A256GCM", "RSA-OAEP"),
                body.replace("\"crv\":\"P-256\"", "\"crv\":\"P-256\",\"d\":\"private-key\""),
                body.replace("\"kty\":\"EC\"", "\"kty\":false"),
                body.replace("\"requestKeyProof\":\"" + "k".repeat(64) + "\"", "\"requestKeyProof\":\"short\""),
                body.replace("\"username\":", "\"deviceBindingId\":\"too-short\",\"username\":"),
                "{\"original\":{\"bodyBase64\":\"e30\"}}",
                " ".repeat(65_537) + body);
    }

    @Test
    void rejectsMissingDuplicateOrMalformedHeadersBeforeUseCase() throws Exception {
        for (HttpHeaders headers : invalidHeaders()) {
            mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON)
                            .headers(headers).content(validBody()))
                    .andExpect(status().isBadRequest());
        }
        verifyNoInteractions(passwords);
    }

    private List<HttpHeaders> invalidHeaders() {
        HttpHeaders missingProof = headers();
        missingProof.remove("DPoP");
        HttpHeaders missingOperation = headers();
        missingOperation.remove("Idempotency-Key");
        HttpHeaders duplicateProof = headers();
        duplicateProof.add("DPoP", DPOP);
        HttpHeaders duplicateOperation = headers();
        duplicateOperation.add("Idempotency-Key", OPERATION);
        HttpHeaders badOperation = headers();
        badOperation.set("Idempotency-Key", "not-a-uuid");
        HttpHeaders shortProof = headers();
        shortProof.set("DPoP", "short");
        HttpHeaders longProof = headers();
        longProof.set("DPoP", "p".repeat(4097));
        HttpHeaders authorization = headers();
        authorization.set(HttpHeaders.AUTHORIZATION, "DPoP token");
        HttpHeaders encoded = headers();
        encoded.set(HttpHeaders.CONTENT_ENCODING, "gzip");
        return List.of(missingProof, missingOperation, duplicateProof, duplicateOperation,
                badOperation, shortProof, longProof, authorization, encoded);
    }

    private HttpHeaders headers() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("DPoP", DPOP);
        headers.set("Idempotency-Key", OPERATION);
        return headers;
    }

    @Test
    void boundsBodyEvenWithoutContentLength() {
        var input = new MockHttpInputMessage(new byte[65_537]);
        assertThatThrownBy(() -> new BoundedJsonBodyAdvice().beforeBodyRead(input, null,
                PasswordLoginRequest.class, JacksonJsonHttpMessageConverter.class))
                .isInstanceOf(HttpMessageNotReadableException.class);
    }

    private static String validBody() {
        return """
                {"appId":"neo-mobile","platform":"ANDROID",
                 "installationId":"install-c02bdd64-1234-4567-8901",
                 "username":"alice","password":"test-password",
                 "tokenEncryptionKey":{"version":1,"algorithm":"ECDH-ES+A256GCM","format":"JWK",
                 "publicJwk":{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}},
                 "requestKeyProof":"%s"}
                """.formatted("A".repeat(43), "A".repeat(43), "k".repeat(64));
    }
}
