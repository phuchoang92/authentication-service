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
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalEndpoint;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpSettings;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.io.ByteArrayOutputStream;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tools.jackson.databind.JsonNode;

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
        var client = client(http, endpoint, key);

        ExternalHttpClient.Response<JsonNode, JsonNode> result =
                client.requestTokens("alice", "private-password");

        assertEquals(400, result.status());
        assertEquals("invalid_grant", result.errorBody().path("error").asString());
        assertEquals("ExternalHttpResponse[redacted]", result.toString());
        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).sendAsync(sent.capture(), any(HttpResponse.BodyHandler.class));
        assertEquals("POST", sent.getValue().method());
        assertEquals(endpoint, sent.getValue().uri());
    }

    @Test
    @SuppressWarnings("unchecked")
    void keepsOAuthResponseRedactedUntilTheAdapterSelectsTheIdToken() throws Exception {
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
        var client = client(http, endpoint, key);

        ExternalHttpClient.Response<JsonNode, JsonNode> result =
                client.requestTokens("alice", "private-password");

        assertEquals("signed-identity", result.successBody().path("id_token").asString());
        assertEquals("ExternalHttpResponse[redacted]", result.toString());
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 500})
    @SuppressWarnings("unchecked")
    void unlistedServerStatusIsRejectedWithoutParsingOAuthTokens(int status) throws Exception {
        URI endpoint = URI.create("https://keycloak.internal/realms/bank/protocol/openid-connect/token");
        HttpClient http = mock(HttpClient.class);
        when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        HttpResponse<byte[]> reply = mock(HttpResponse.class);
        when(reply.statusCode()).thenReturn(status);
        when(reply.headers()).thenReturn(HttpHeaders.of(
                Map.of("Content-Type", List.of("application/json")), (name, value) -> true));
        when(reply.body()).thenReturn("{\"error\":\"server-error\"}"
                .getBytes(StandardCharsets.UTF_8));
        when(http.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(reply));
        var key = new ECKeyGenerator(Curve.P_256).keyID("auth-client-test").generate();
        var client = client(http, endpoint, key);

        assertThrows(com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpRequestFailedException.class,
                () -> client.requestTokens("alice", "private-password"));
        verify(http, times(1)).sendAsync(any(HttpRequest.class),
                any(HttpResponse.BodyHandler.class));
    }

    @Test
    void secretModeSendsEncodedCredentialsWithoutAnAssertion() throws Exception {
        HttpClient http = invalidGrantHttp();
        var authentication = new KeycloakClientSecretAuthentication("bank-auth-secret", "test&=+ñ secret");
        var client = client(http, authentication);
        client.requestTokens("alice", "password&+value");

        Map<String, String> fields = requestFields(http);
        assertThat(fields).containsEntry("grant_type", "password").containsEntry("scope", "openid")
                .containsEntry("client_id", "bank-auth-secret").containsEntry("client_secret", "test&=+ñ secret")
                .containsEntry("username", "alice").containsEntry("password", "password&+value")
                .doesNotContainKeys("client_assertion", "client_assertion_type");
        assertThat(authentication.toString()).isEqualTo("KeycloakClientSecretAuthentication[redacted]");
    }

    @Test
    void jwtModeUsesConfiguredClientIdInBothFormAndAssertionWithoutSecret() throws Exception {
        HttpClient http = invalidGrantHttp();
        URI endpoint = URI.create("https://keycloak.internal/realms/bank/protocol/openid-connect/token");
        var key = new ECKeyGenerator(Curve.P_256).keyID("auth-client-test").generate();
        var authentication = new KeycloakPrivateKeyJwtAuthentication(
                new PrivateKeyJwtFactory("bank-auth-jwt", endpoint, key),
                Clock.fixed(Instant.parse("2026-10-11T12:00:00Z"), ZoneOffset.UTC));
        client(http, authentication).requestTokens("alice", "test-password");
        Map<String, String> fields = requestFields(http);
        assertThat(fields).containsEntry("client_id", "bank-auth-jwt")
                .containsEntry("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .doesNotContainKey("client_secret");
        var claims = SignedJWT.parse(fields.get("client_assertion")).getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo("bank-auth-jwt");
        assertThat(claims.getSubject()).isEqualTo("bank-auth-jwt");

    }

    @SuppressWarnings("unchecked")
    private static HttpClient invalidGrantHttp() throws Exception {
        HttpClient http = mock(HttpClient.class);
        when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        HttpResponse<byte[]> reply = mock(HttpResponse.class);
        when(reply.statusCode()).thenReturn(400);
        when(reply.headers()).thenReturn(HttpHeaders.of(
                Map.of("Content-Type", List.of("application/json")), (name, value) -> true));
        when(reply.body()).thenReturn("{\"error\":\"invalid_grant\"}".getBytes(StandardCharsets.UTF_8));
        when(http.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(reply));
        return http;
    }

    private DirectGrantTokenClient client(HttpClient http, KeycloakClientAuthentication authentication) {
        URI endpoint = URI.create("https://keycloak.internal/realms/bank/protocol/openid-connect/token");
        ExternalEndpoint<JsonNode, JsonNode> tokenEndpoint = KeycloakTokenEndpoints.directGrant(endpoint);
        var settings = new ExternalHttpSettings(endpoint.resolve("/"), Duration.ofSeconds(1),
                65_536, Set.of(tokenEndpoint.route()));
        return new DirectGrantTokenClient(new ExternalHttpClient(http, settings), tokenEndpoint, authentication);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> requestFields(HttpClient http) throws Exception {
        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).sendAsync(sent.capture(), any(HttpResponse.BodyHandler.class));
        var body = new CompletableFuture<byte[]>();
        sent.getValue().bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<ByteBuffer>() {
            private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

            public void onSubscribe(Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
            public void onNext(ByteBuffer buffer) {
                byte[] part = new byte[buffer.remaining()];
                buffer.get(part);
                bytes.writeBytes(part);
            }
            public void onError(Throwable failure) { body.completeExceptionally(failure); }
            public void onComplete() { body.complete(bytes.toByteArray()); }
        });
        String encoded = new String(body.get(1, TimeUnit.SECONDS), StandardCharsets.UTF_8);
        return java.util.Arrays.stream(encoded.split("&")).map(field -> field.split("=", 2))
                .collect(Collectors.toMap(field -> URLDecoder.decode(field[0], StandardCharsets.UTF_8),
                        field -> URLDecoder.decode(field[1], StandardCharsets.UTF_8)));
    }

    private DirectGrantTokenClient client(HttpClient http, URI endpoint,
                                          com.nimbusds.jose.jwk.ECKey key) {
        ExternalEndpoint<JsonNode, JsonNode> tokenEndpoint = KeycloakTokenEndpoints.directGrant(endpoint);
        ExternalHttpSettings settings = new ExternalHttpSettings(endpoint.resolve("/"),
                Duration.ofSeconds(1), 65_536, Set.of(tokenEndpoint.route()));
        return new DirectGrantTokenClient(new ExternalHttpClient(http, settings), tokenEndpoint,
                new KeycloakPrivateKeyJwtAuthentication(
                        new PrivateKeyJwtFactory("authentication-service", endpoint, key),
                        Clock.fixed(Instant.parse("2026-10-11T12:00:00Z"), ZoneOffset.UTC)));
    }
}
