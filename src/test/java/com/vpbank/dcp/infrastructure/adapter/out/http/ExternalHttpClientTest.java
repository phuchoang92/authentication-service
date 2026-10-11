package com.vpbank.dcp.infrastructure.adapter.out.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    @Test
    void strictResponseParsingRejectsDuplicateMembers() {
        var http = client(200, "{\"status\":\"ok\",\"status\":\"altered\"}");

        assertThrows(ExternalHttpRequestFailedException.class,
                () -> http.get("/status", JsonNode.class));
    }

    @Test
    void rejectsUnlistedEndpointBeforeSending() {
        var http = client(200, "{}");

        assertThrows(ExternalHttpRequestFailedException.class,
                () -> http.get("/other", JsonNode.class));
    }

    @Test
    void redactsResponseAndFormDiagnostics() {
        var http = client(200, "{\"access_token\":\"secret\"}");
        var form = new ExternalForm().add("password", "private-password");
        var reply = http.get("/status", JsonNode.class);

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
                () -> http.get("/status", JsonNode.class));
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
                Set.of(ExternalHttpSettings.Route.exact("GET", "/status")));
        return new ExternalHttpClient(client, settings);
    }
}
