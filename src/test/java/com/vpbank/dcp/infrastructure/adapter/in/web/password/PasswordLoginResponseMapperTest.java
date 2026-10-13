package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import com.vpbank.dcp.core.port.out.session.SessionActivationSnapshot;
import com.vpbank.dcp.core.port.out.session.SessionActivationContext;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.domain.session.SessionAssurance;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginActiveResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginErrorResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginProcessingResponse;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class PasswordLoginResponseMapperTest {
    private static final Instant NOW = Instant.parse("2026-10-12T00:00:00Z");
    private static final UUID OPERATION = UUID.fromString("44444444-4444-4444-8444-444444444444");
    private static final UUID BINDING = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private final PasswordLoginResponseMapper mapper = new PasswordLoginResponseMapper(Clock.fixed(NOW, ZoneOffset.UTC));
    private final JsonMapper json = new JsonMapper();

    @Test
    void activeDtoPreservesPublicJsonFieldsHeadersAndSafeOutput() {
        var response = mapper.map(OPERATION, new PasswordLoginResult.Active(session(
                NOW.plusSeconds(900), NOW.plusSeconds(3600))));
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isInstanceOf(PasswordLoginActiveResponse.class);
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("DPoP-Nonce")).isEqualTo("nonce-test-only");
        JsonNode body = json.readTree(json.writeValueAsString(response.getBody()));
        assertThat(fields(body)).containsExactlyInAnyOrder("status", "tokenEnvelope", "receipt",
                "expires_in", "scope", "session", "security");
        assertThat(body).isEqualTo(json.readTree("""
                {"status":"ACTIVE","tokenEnvelope":"encrypted-envelope-test-only",
                 "receipt":"signed-receipt-test-only","expires_in":3600,"scope":"banking",
                 "session":{"idleExpiresAt":"2026-10-12T00:15:00Z","absoluteExpiresAt":"2026-10-12T01:00:00Z"},
                 "security":{"deviceTrusted":true,"deviceBindingId":"22222222-2222-4222-8222-222222222222",
                 "biometricLoginEnabled":true,"assurance":{"devicePossession":"MFA_KEY_POSSESSION",
                 "platformEvidence":"NONE","biometricEnforcement":"NOT_APPLICABLE"}}}
                """));
        assertThat(response.getBody().toString()).doesNotContain("encrypted-envelope", "signed-receipt");
        assertThat(body.toString()).doesNotContain("password", "lookupDigest", "generation", "sessionId", "dpopNonce");
    }

    @Test
    void processingDtoKeepsTheOriginalOperationAndHasNoTokenDelivery() {
        var response = mapper.map(OPERATION, new PasswordLoginResult.Processing());
        assertThat(response.getStatusCode().value()).isEqualTo(202);
        assertThat(response.getBody()).isInstanceOf(PasswordLoginProcessingResponse.class);
        JsonNode body = json.readTree(json.writeValueAsString(response.getBody()));
        assertThat(fields(body)).containsExactlyInAnyOrder("status", "operationId", "nextAction", "correlationId");
        assertThat(body.path("status").asText()).isEqualTo("PROCESSING");
        assertThat(body.path("operationId").asText()).isEqualTo(OPERATION.toString());
        assertThat(body.path("nextAction").asText()).isEqualTo("POLL_RESULT");
        assertThat(UUID.fromString(body.path("correlationId").asText())).isNotNull();
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
    }

    @Test
    void errorDtosPreserveStatusCodeAndSafeProblemContract() {
        problem(new PasswordLoginResult.Rejected(), 401, "REQUEST_REJECTED");
        problem(new PasswordLoginResult.Conflict(), 409, "STATE_CONFLICT");
        problem(new PasswordLoginResult.TemporarilyUnavailable(), 503, "TEMPORARILY_UNAVAILABLE");
        problem(new PasswordLoginResult.Active(session(NOW, NOW.plusSeconds(3600))),
                503, "TEMPORARILY_UNAVAILABLE");
    }

    @Test
    void remainingExpiryIsStillBoundedAndDatesRemainStringsWithFractionalSeconds() {
        var response = mapper.map(OPERATION, new PasswordLoginResult.Active(session(
                NOW.plusSeconds(30).plusNanos(123456000), NOW.plusSeconds(90))));
        JsonNode body = json.readTree(json.writeValueAsString(response.getBody()));
        assertThat(body.path("expires_in").asLong()).isEqualTo(90);
        assertThat(body.path("session").path("idleExpiresAt").asText()).isEqualTo("2026-10-12T00:00:30.123456Z");
    }

    private void problem(PasswordLoginResult result, int status, String code) {
        var response = mapper.map(OPERATION, result);
        assertThat(response.getStatusCode().value()).isEqualTo(status);
        assertThat(response.getBody()).isInstanceOf(PasswordLoginErrorResponse.class);
        JsonNode body = json.readTree(json.writeValueAsString(response.getBody()));
        assertThat(fields(body)).containsExactlyInAnyOrder("code", "message", "correlationId", "nextAction");
        assertThat(body.path("code").asText()).isEqualTo(code);
        assertThat(body.path("message").asText()).isEqualTo("The request was rejected");
        assertThat(body.path("nextAction").asText()).isEqualTo("RETRY_LATER");
        assertThat(UUID.fromString(body.path("correlationId").asText())).isNotNull();
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("DPoP-Nonce")).isNull();
    }

    private PreparedSession session(Instant idle, Instant absolute) {
        var snapshot = mock(SessionActivationSnapshot.class);
        when(snapshot.context()).thenReturn(new SessionActivationContext(UUID.randomUUID(),
                UUID.randomUUID(), UUID.randomUUID(), "mobile", BINDING));
        when(snapshot.biometricLoginEnabled()).thenReturn(true);
        when(snapshot.assurance()).thenReturn(new SessionAssurance(SessionAssurance.DevicePossession.MFA_KEY_POSSESSION,
                SessionAssurance.PlatformEvidence.NONE, SessionAssurance.BiometricEnforcement.NOT_APPLICABLE));
        var session = mock(PreparedSession.class);
        when(session.snapshot()).thenReturn(snapshot);
        when(session.deadlines()).thenReturn(new SessionDeadlines(idle, absolute));
        when(session.tokenEnvelope()).thenReturn("encrypted-envelope-test-only");
        when(session.receipt()).thenReturn("signed-receipt-test-only");
        when(session.dpopNonce()).thenReturn("nonce-test-only");
        return session;
    }

    private Set<String> fields(JsonNode body) {
        return StreamSupport.stream(body.properties().spliterator(), false)
                .map(java.util.Map.Entry::getKey).collect(Collectors.toSet());
    }
}
