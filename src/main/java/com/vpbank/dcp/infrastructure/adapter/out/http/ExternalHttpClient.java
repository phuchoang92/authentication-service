package com.vpbank.dcp.infrastructure.adapter.out.http;

import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.Objects;

/**
 * Sends bounded JSON requests to an allowlisted external service. Endpoint contracts
 * select which statuses may be parsed; adapters interpret their business meaning.
 */
public final class ExternalHttpClient {

    private final BoundedJsonExchange exchange;
    private final ExternalHttpSettings settings;
    private final JsonMapper json = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    public ExternalHttpClient(HttpClient client, ExternalHttpSettings settings) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.exchange = new BoundedJsonExchange(client, settings.origin(), settings.deadline(),
                settings.maximumResponseBytes(), settings.allowedRoutes().stream()
                .map(ExternalHttpSettings.Route::allowed).collect(
                        java.util.stream.Collectors.toUnmodifiableSet()));
    }

    public <T> Response<T> getJson(ExternalEndpoint<T> endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        endpoint.requireKind(ExternalEndpoint.Kind.GET_JSON);
        return read(request(endpoint.path()).GET().build(), endpoint);
    }

    public <T> Response<T> postJson(ExternalEndpoint<T> endpoint, Object body) {
        Objects.requireNonNull(endpoint, "endpoint");
        endpoint.requireKind(ExternalEndpoint.Kind.POST_JSON);
        Objects.requireNonNull(body, "body");
        try {
            byte[] encoded = json.writeValueAsBytes(body);
            HttpRequest request = request(endpoint.path()).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(encoded)).build();
            return read(request, endpoint);
        } catch (JacksonException failure) {
            throw new ExternalRequestEncodingException(failure);
        }
    }

    public <T> Response<T> postForm(ExternalEndpoint<T> endpoint, ExternalForm body) {
        Objects.requireNonNull(endpoint, "endpoint");
        endpoint.requireKind(ExternalEndpoint.Kind.POST_FORM);
        Objects.requireNonNull(body, "body");
        HttpRequest request = request(endpoint.path())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body.bytes())).build();
        return read(request, endpoint);
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(settings.origin().resolve(path))
                .timeout(settings.deadline())
                .header("Accept", "application/json")
                .header("Accept-Encoding", "identity");
    }

    private <T> Response<T> read(HttpRequest request, ExternalEndpoint<T> endpoint) {
        BoundedJsonExchange.JsonResponse reply = exchange.send(request);
        if (!endpoint.accepts(reply.status())) {
            throw new ExternalHttpRequestFailedException(reply.status());
        }
        try {
            T value = json.readValue(reply.body(), endpoint.responseType());
            if (value == null) {
                throw new ExternalHttpRequestFailedException();
            }
            return new Response<>(reply.status(), value);
        } catch (JacksonException failure) {
            throw new ExternalHttpRequestFailedException(failure);
        }
    }

    /**
     * A response may contain tokens. Its diagnostic representation is always redacted.
     */
    public record Response<T>(int status, T body) {
        @Override
        public String toString() {
            return "ExternalHttpResponse[redacted]";
        }
    }
}
