package com.vpbank.dcp.infrastructure.adapter.out.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

class ExternalHttpClientTest {

    private static final URI ORIGIN = URI.create("https://partner.internal");
    private static final ExternalEndpoint<JsonNode, Void> STATUS = ExternalEndpoint.getJson(
            "/status", JsonNode.class, Set.of(200));

    @Test
    void strictResponseParsingRejectsDuplicateMembers() {
        var http = client(200, "{\"status\":\"ok\",\"status\":\"altered\"}");

        assertThrows(ExternalHttpRequestFailedException.class,
                () -> http.getJson(STATUS));
    }

    @Test
    void rejectsUnlistedEndpointBeforeSending() {
        var http = client(200, "{}");

        assertThrows(ExternalHttpRequestFailedException.class,
                () -> http.getJson(ExternalEndpoint.getJson("/other", JsonNode.class,
                        Set.of(200))));
    }

    @Test
    void redactsResponseAndFormDiagnostics() {
        var http = client(200, "{\"access_token\":\"secret\"}");
        var form = new ExternalForm().add("password", "private-password");
        var reply = http.getJson(STATUS);

        assertEquals("ExternalHttpResponse[redacted]", reply.toString());
        assertEquals("ExternalForm[redacted]", form.toString());
        assertTrue(!reply.toString().contains("secret"));
    }

    @Test
    void encodesPathSegmentWithoutFormEncoding() {
        assertEquals("CUST%3A001", ExternalPath.segment("CUST:001"));
        assertEquals("with%20space", ExternalPath.segment("with space"));
    }

    @Test
    void formEncodingHandlesReservedCharactersAndRejectsDuplicateFields() {
        var form = new ExternalForm().add("password", "one&two + three");

        assertEquals("password=one%26two+%2B+three",
                new String(form.bytes(), StandardCharsets.UTF_8));
        assertThrows(InvalidExternalHttpSettingsException.class,
                () -> form.add("password", "replacement"));
    }

    @Test
    void malformedJsonIsDependencyFailure() {
        var http = client(200, "{\"broken\":");

        assertThrows(ExternalHttpRequestFailedException.class,
                () -> http.getJson(STATUS));
    }

    @Test
    void rejectsUnlistedStatusBeforeParsingSuccessDto() {
        var http = client(400, "{\"error\":\"not-a-status-dto\"}");

        ExternalHttpRequestFailedException failure = assertThrows(
                ExternalHttpRequestFailedException.class, () -> http.getJson(STATUS));

        assertEquals(400, failure.statusCode());
        assertNull(failure.getCause());
        assertTrue(!failure.toString().contains("not-a-status-dto"));
    }

    @Test
    void bindsOnlyOneEncodedPathSegmentAndDerivesAllowlistFromTemplate() {
        ExternalEndpoint<JsonNode, Void> endpoint = ExternalEndpoint.getJson(
                "/customers/{customerId}/status", JsonNode.class, Set.of(200));
        assertTrue(endpoint.route().path().matcher("/customers/CUST%3A001/status").matches());
        assertTrue(!endpoint.route().path().matcher("/customers/CUST/001/status").matches());
        assertThrows(InvalidExternalHttpSettingsException.class,
                () -> endpoint.bindSegment("wrongName", "CUST:001"));
        assertThrows(InvalidExternalHttpSettingsException.class,
                () -> ExternalEndpoint.getJson("/customers/prefix{customerId}/status",
                        JsonNode.class, Set.of(200)));
        assertEquals("/customers/CUST%3A001/status",
                endpoint.bindSegment("customerId", "CUST:001").path());
    }

    @Test
    void methodKindCannotBeChangedAtCallSite() {
        var http = client(200, "{}");
        assertThrows(InvalidExternalHttpSettingsException.class,
                () -> http.postJson(STATUS, Map.of("value", 1)));
    }

    @Test
    void parsesDeclaredErrorIntoItsOwnDtoWithoutTreatingItAsSuccess() {
        ExternalEndpoint<JsonNode, JsonNode> endpoint = ExternalEndpoint.getJson(
                "/status", JsonNode.class, Set.of(200), JsonNode.class, Set.of(404));
        ExternalHttpClient.Response<JsonNode, JsonNode> reply =
                client(404, "{\"code\":\"NOT_FOUND\"}").getJson(endpoint);

        assertTrue(!reply.isSuccess());
        assertEquals("NOT_FOUND", reply.errorBody().path("code").asString());
        assertThrows(IllegalStateException.class, reply::successBody);
        assertEquals("ExternalHttpResponse[redacted]", reply.toString());
    }

    @SuppressWarnings("unchecked")
    private ExternalHttpClient client(int status, String body) {
        HttpClient client = mock(HttpClient.class);
        when(client.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        HttpResponse<byte[]> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.headers()).thenReturn(HttpHeaders.of(
                Map.of("Content-Type", List.of("application/json")), (name, value) -> true));
        when(response.body()).thenReturn(body.getBytes(StandardCharsets.UTF_8));
        when(client.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(response));
        ExternalHttpSettings settings = new ExternalHttpSettings(ORIGIN,
                Duration.ofSeconds(1), 4096,
                Set.of(STATUS.route()));
        return new ExternalHttpClient(client, settings);
    }
}
