package com.vpbank.dcp.infrastructure.adapter.out.customer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectoryUnavailableException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.Test;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

class HttpCustomerDirectoryTest {

    private final JsonMapper json = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    @Test
    void decodesCompleteSnapshotWithoutInferringEligibility() {
        var directory = directory();

        var snapshot = directory.decode("""
                {"customerId":"CUST-001","status":"BLOCKED","statusVersion":42,
                 "lastAccessBlockVersion":42,"checkedAt":"2026-10-11T03:10:00Z"}
                """);

        assertEquals(CustomerStatus.BLOCKED, snapshot.status());
        assertEquals(42, snapshot.lastAccessBlockVersion());
    }

    @Test
    void missingWatermarkAndUnknownFieldAreUnavailable() {
        var directory = directory();

        assertThrows(CustomerDirectoryUnavailableException.class, () -> directory.decode("""
                {"customerId":"CUST-001","status":"ELIGIBLE","statusVersion":43,
                 "checkedAt":"2026-10-11T03:10:00Z"}
                """));
        assertThrows(CustomerDirectoryUnavailableException.class, () -> directory.decode("""
                {"customerId":"CUST-001","status":"ELIGIBLE","statusVersion":43,
                 "lastAccessBlockVersion":42,"checkedAt":"2026-10-11T03:10:00Z",
                 "allow":true}
                """));
    }

    @Test
    @SuppressWarnings("unchecked")
    void statusReplyMustBelongToRequestedCustomer() {
        HttpClient client = mock(HttpClient.class);
        when(client.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        HttpResponse<byte[]> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        when(response.headers()).thenReturn(HttpHeaders.of(
                Map.of("Content-Type", List.of("application/json")), (name, value) -> true));
        when(response.body()).thenReturn("""
                {"customerId":"CUST-OTHER","status":"ELIGIBLE","statusVersion":43,
                 "lastAccessBlockVersion":42,"checkedAt":"2026-10-11T03:10:00Z"}
                """.getBytes(StandardCharsets.UTF_8));
        when(client.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(response));
        var directory = new HttpCustomerDirectory(client, URI.create("https://customer.internal"),
                Duration.ofSeconds(1), json);

        assertThrows(CustomerDirectoryUnavailableException.class,
                () -> directory.currentStatus("CUST-001"));
    }

    @Test
    void plainHttpOriginIsNotAccepted() {
        assertThrows(InvalidCustomerDirectoryConfigurationException.class,
                () -> new HttpCustomerDirectory(HttpClient.newHttpClient(),
                        URI.create("http://customer.internal"), Duration.ofSeconds(1), json));
    }

    @Test
    @SuppressWarnings("unchecked")
    void resolveUsesBoundedTransportAndMapsCustomerReply() {
        HttpClient client = mock(HttpClient.class);
        when(client.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        HttpResponse<byte[]> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        when(response.headers()).thenReturn(HttpHeaders.of(
                Map.of("Content-Type", List.of("application/json")), (name, value) -> true));
        when(response.body()).thenReturn("""
                {"customerId":"CUST-001","status":"ELIGIBLE","statusVersion":43,
                 "lastAccessBlockVersion":42,"checkedAt":"2026-10-11T03:10:00Z"}
                """.getBytes(StandardCharsets.UTF_8));
        when(client.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(response));
        var directory = new HttpCustomerDirectory(client, URI.create("https://customer.internal"),
                Duration.ofSeconds(1), json);

        var customer = directory.resolve(new VerifiedProviderIdentity(
                "https://keycloak.internal/realms/bank", "immutable-sub"));

        assertEquals("CUST-001", customer.customerId());
        assertEquals(CustomerStatus.ELIGIBLE, customer.status());
        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(client).sendAsync(sent.capture(), any(HttpResponse.BodyHandler.class));
        assertEquals("POST", sent.getValue().method());
        assertEquals("/internal/v1/customer-authentication/resolve",
                sent.getValue().uri().getPath());
    }

    private HttpCustomerDirectory directory() {
        return new HttpCustomerDirectory(HttpClient.newHttpClient(),
                URI.create("https://customer.internal"), Duration.ofSeconds(1), json);
    }
}
