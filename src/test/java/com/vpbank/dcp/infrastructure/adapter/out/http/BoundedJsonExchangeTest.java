package com.vpbank.dcp.infrastructure.adapter.out.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import org.junit.jupiter.api.Test;

class BoundedJsonExchangeTest {

    private static final URI ORIGIN = URI.create("https://customer.internal");
    private static final String PATH = "/internal/v1/customer-authentication/resolve";

    @Test
    void acceptsOnlyAllowlistedHttpsRequestAndRedactsResponse() {
        HttpClient client = clientWithResponse(200, Map.of("Content-Type", List.of("application/json")),
                "{\"ok\":true}".getBytes(StandardCharsets.UTF_8));
        BoundedJsonExchange exchange = exchange(client, Duration.ofSeconds(1), 64);

        BoundedJsonExchange.JsonResponse response = exchange.send(request(PATH));

        assertEquals(200, response.status());
        assertEquals("{\"ok\":true}", response.body());
        assertEquals("JsonResponse[redacted]", response.toString());
        assertThrows(PartnerHttpFailureException.class,
                () -> exchange.send(request("/internal/v1/not-allowed")));
        assertThrows(PartnerHttpFailureException.class,
                () -> exchange.send(HttpRequest.newBuilder(URI.create("https://other.internal" + PATH))
                        .GET().build()));
        verify(client, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void rejectsEncodedBodiesAndMalformedUtf8() {
        BoundedJsonExchange encoded = exchange(clientWithResponse(200,
                Map.of("Content-Type", List.of("application/json"),
                        "Content-Encoding", List.of("gzip")), new byte[] {1}),
                Duration.ofSeconds(1), 64);
        assertThrows(PartnerHttpFailureException.class, () -> encoded.send(request(PATH)));

        BoundedJsonExchange malformed = exchange(clientWithResponse(200,
                Map.of("Content-Type", List.of("application/json")), new byte[] {(byte) 0xc3}),
                Duration.ofSeconds(1), 64);
        assertThrows(PartnerHttpFailureException.class, () -> malformed.send(request(PATH)));
    }

    @Test
    void deadlineCancelsTheExchangeWithoutRetry() {
        HttpClient client = mock(HttpClient.class);
        when(client.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        CompletableFuture<HttpResponse<byte[]>> pending = new CompletableFuture<>();
        when(client.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(pending);
        BoundedJsonExchange exchange = exchange(client, Duration.ofMillis(5), 64);

        assertThrows(PartnerHttpFailureException.class, () -> exchange.send(request(PATH)));

        assertTrue(pending.isCancelled());
        verify(client, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void subscriberCancelsBeforeBufferingOversizedBody() {
        var subscriber = new LimitedBodySubscriber(4);
        Flow.Subscription subscription = mock(Flow.Subscription.class);
        subscriber.onSubscribe(subscription);
        subscriber.onNext(List.of(ByteBuffer.wrap(new byte[] {1, 2, 3})));
        subscriber.onNext(List.of(ByteBuffer.wrap(new byte[] {4, 5})));

        assertThrows(ExecutionException.class, () -> subscriber.getBody().get());
        verify(subscription).cancel();
    }

    private BoundedJsonExchange exchange(HttpClient client, Duration timeout, int limit) {
        return new BoundedJsonExchange(client, ORIGIN, timeout, limit,
                Set.of(BoundedJsonExchange.AllowedEndpoint.exact("GET", PATH)));
    }

    private HttpRequest request(String path) {
        return HttpRequest.newBuilder(ORIGIN.resolve(path)).timeout(Duration.ofSeconds(1)).GET().build();
    }

    @SuppressWarnings("unchecked")
    private HttpClient clientWithResponse(int status, Map<String, List<String>> headers, byte[] body) {
        HttpClient client = mock(HttpClient.class);
        when(client.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        HttpResponse<byte[]> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.headers()).thenReturn(HttpHeaders.of(headers, (name, value) -> true));
        when(response.body()).thenReturn(body);
        when(client.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(response));
        return client;
    }
}
