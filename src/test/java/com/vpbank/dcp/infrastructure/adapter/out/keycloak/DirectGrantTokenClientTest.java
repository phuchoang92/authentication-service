package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.keycloak.KeycloakVerificationUnavailableException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class DirectGrantTokenClientTest {

    @Test
    @SuppressWarnings("unchecked")
    void sendsOneConfidentialGrantThroughBoundedTransport() throws Exception {
        URI endpoint = URI.create("https://keycloak.internal/realms/bank/protocol/openid-connect/token");
        HttpClient http = mock(HttpClient.class);
        when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        HttpResponse<byte[]> reply = mock(HttpResponse.class);
        when(reply.statusCode()).thenReturn(400);
        when(reply.headers()).thenReturn(HttpHeaders.of(
                Map.of("Content-Type", List.of("application/json")), (name, value) -> true));
        when(reply.body()).thenReturn("{\"error\":\"invalid_grant\"}"
                .getBytes(StandardCharsets.UTF_8));
        when(http.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(reply));
        var key = new ECKeyGenerator(Curve.P_256).keyID("auth-client-test").generate();
        var client = new DirectGrantTokenClient(http, endpoint,
                new PrivateKeyJwtFactory(endpoint, key), Duration.ofSeconds(1),
                Clock.fixed(Instant.parse("2026-10-11T12:00:00Z"), ZoneOffset.UTC));

        DirectGrantTokenClient.Response result = client.verify(
                new PasswordVerification("alice", "private-password"));

        assertEquals(400, result.status());
        assertEquals("invalid_grant", result.errorCode());
        assertEquals("DirectGrantResponse[redacted]", result.toString());
        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).sendAsync(sent.capture(), any(HttpResponse.BodyHandler.class));
        assertEquals("POST", sent.getValue().method());
        assertEquals(endpoint, sent.getValue().uri());
    }

    @Test
    @SuppressWarnings("unchecked")
    void discardsAccessAndRefreshTokensAtPartnerBoundary() throws Exception {
        URI endpoint = URI.create("https://keycloak.internal/realms/bank/protocol/openid-connect/token");
        HttpClient http = mock(HttpClient.class);
        when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        HttpResponse<byte[]> reply = mock(HttpResponse.class);
        when(reply.statusCode()).thenReturn(200);
        when(reply.headers()).thenReturn(HttpHeaders.of(
                Map.of("Content-Type", List.of("application/json")), (name, value) -> true));
        when(reply.body()).thenReturn("""
                {"access_token":"access-secret","refresh_token":"refresh-secret",
                 "id_token":"signed-identity"}
                """.getBytes(StandardCharsets.UTF_8));
        when(http.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(reply));
        var key = new ECKeyGenerator(Curve.P_256).keyID("auth-client-test").generate();
        var client = new DirectGrantTokenClient(http, endpoint,
                new PrivateKeyJwtFactory(endpoint, key), Duration.ofSeconds(1),
                Clock.fixed(Instant.parse("2026-10-11T12:00:00Z"), ZoneOffset.UTC));

        DirectGrantTokenClient.Response result = client.verify(
                new PasswordVerification("alice", "private-password"));

        assertEquals("signed-identity", result.identityToken());
        assertEquals("DirectGrantResponse[redacted]", result.toString());
    }

    @Test
    @SuppressWarnings("unchecked")
    void unlistedServerStatusIsRejectedWithoutParsingOAuthTokens() throws Exception {
        URI endpoint = URI.create("https://keycloak.internal/realms/bank/protocol/openid-connect/token");
        HttpClient http = mock(HttpClient.class);
        when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        HttpResponse<byte[]> reply = mock(HttpResponse.class);
        when(reply.statusCode()).thenReturn(500);
        when(reply.headers()).thenReturn(HttpHeaders.of(
                Map.of("Content-Type", List.of("application/json")), (name, value) -> true));
        when(reply.body()).thenReturn("{\"error\":\"server-error\"}"
                .getBytes(StandardCharsets.UTF_8));
        when(http.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(reply));
        var key = new ECKeyGenerator(Curve.P_256).keyID("auth-client-test").generate();
        var client = new DirectGrantTokenClient(http, endpoint,
                new PrivateKeyJwtFactory(endpoint, key), Duration.ofSeconds(1),
                Clock.fixed(Instant.parse("2026-10-11T12:00:00Z"), ZoneOffset.UTC));

        assertThrows(KeycloakVerificationUnavailableException.class,
                () -> client.verify(new PasswordVerification("alice", "private-password")));
        verify(http, times(1)).sendAsync(any(HttpRequest.class),
                any(HttpResponse.BodyHandler.class));
    }
}
