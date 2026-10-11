package com.vpbank.dcp.infrastructure.adapter.out.customer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectoryUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpRequestFailedException;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpSettings;
import com.vpbank.dcp.infrastructure.adapter.out.http.InvalidExternalHttpSettingsException;
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

class HttpCustomerDirectoryTest {

    @Test
    void decodesCompleteSnapshotWithoutInferringEligibility() {
        var directory = directoryWithReply("""
                {"customerId":"CUST-001","status":"BLOCKED","statusVersion":42,
                 "lastAccessBlockVersion":42,"checkedAt":"2026-10-11T03:10:00Z"}
                """);
        var snapshot = directory.resolve(identity());

        assertEquals(CustomerStatus.BLOCKED, snapshot.status());
        assertEquals(42, snapshot.lastAccessBlockVersion());
    }

    @Test
    void missingWatermarkAndUnknownFieldAreUnavailable() {
        assertThrows(CustomerDirectoryUnavailableException.class, () -> directoryWithReply("""
                {"customerId":"CUST-001","status":"ELIGIBLE","statusVersion":43,
                 "checkedAt":"2026-10-11T03:10:00Z"}
                """).resolve(identity()));
        assertThrows(CustomerDirectoryUnavailableException.class, () -> directoryWithReply("""
                {"customerId":"CUST-001","status":"ELIGIBLE","statusVersion":43,
                 "lastAccessBlockVersion":42,"checkedAt":"2026-10-11T03:10:00Z",
                 "allow":true}
                """).resolve(identity()));
    }

    @Test
    void invalidCustomerStateAndTimestampAreUnavailable() {
        assertThrows(CustomerDirectoryUnavailableException.class, () -> directoryWithReply("""
                {"customerId":"CUST-001","status":"BLOCKED","statusVersion":43,
                 "lastAccessBlockVersion":42,"checkedAt":"2026-10-11T03:10:00Z"}
                """).resolve(identity()));
        assertThrows(CustomerDirectoryUnavailableException.class, () -> directoryWithReply("""
                {"customerId":"CUST-001","status":"ELIGIBLE","statusVersion":43,
                 "lastAccessBlockVersion":42,"checkedAt":"not-a-dateZ"}
                """).resolve(identity()));
    }

    @Test
    void nonSuccessStatusDoesNotParseCustomerErrorBody() {
        for (int status : List.of(400, 404, 503)) {
            HttpCustomerDirectory directory = directoryWithReply(status,
                    "{\"error\":\"customer-error\"}");
            CustomerDirectoryUnavailableException failure = assertThrows(
                    CustomerDirectoryUnavailableException.class,
                    () -> directory.resolve(identity()));
            ExternalHttpRequestFailedException transport = assertInstanceOf(
                    ExternalHttpRequestFailedException.class, failure.getCause());
            assertEquals(status, transport.statusCode());
            assertNull(transport.getCause());
        }
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
        var directory = directory(client, URI.create("https://customer.internal"));

        assertThrows(CustomerDirectoryUnavailableException.class,
                () -> directory.currentStatus("CUST-001"));
    }

    @Test
    void plainHttpOriginIsNotAccepted() {
        assertThrows(InvalidExternalHttpSettingsException.class,
                () -> directory(HttpClient.newHttpClient(),
                        URI.create("http://customer.internal")));
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
        var directory = directory(client, URI.create("https://customer.internal"));

        var customer = directory.resolve(identity());

        assertEquals("CUST-001", customer.customerId());
        assertEquals(CustomerStatus.ELIGIBLE, customer.status());
        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(client).sendAsync(sent.capture(), any(HttpResponse.BodyHandler.class));
        assertEquals("POST", sent.getValue().method());
        assertEquals("/internal/v1/customer-authentication/resolve",
                sent.getValue().uri().getPath());
    }

    @SuppressWarnings("unchecked")
    private HttpCustomerDirectory directoryWithReply(String body) {
        return directoryWithReply(200, body);
    }

    @SuppressWarnings("unchecked")
    private HttpCustomerDirectory directoryWithReply(int status, String body) {
        HttpClient client = mock(HttpClient.class);
        when(client.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        HttpResponse<byte[]> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.headers()).thenReturn(HttpHeaders.of(
                Map.of("Content-Type", List.of("application/json")), (name, value) -> true));
        when(response.body()).thenReturn(body.getBytes(StandardCharsets.UTF_8));
        when(client.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(response));
        return directory(client, URI.create("https://customer.internal"));
    }

    private HttpCustomerDirectory directory(HttpClient client, URI origin) {
        ExternalHttpSettings settings = new ExternalHttpSettings(origin, Duration.ofSeconds(1),
                4096, CustomerHttpEndpoints.allowedRoutes());
        return new HttpCustomerDirectory(new ExternalHttpClient(client, settings));
    }

    private VerifiedProviderIdentity identity() {
        return new VerifiedProviderIdentity("https://keycloak.internal/realms/bank", "immutable-sub");
    }
}
