package com.vpbank.dcp.infrastructure.adapter.out.http;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.Objects;
import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Sends bounded JSON requests to an allowlisted external service. The caller decides
 * what each HTTP status means; this class handles only HTTP and JSON mechanics.
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

    public <T> Response<T> get(String path, Class<T> responseType) {
        return read(request(path).GET().build(), responseType);
    }

    public <T> Response<T> postJson(String path, Object body, Class<T> responseType) {
        Objects.requireNonNull(body, "body");
        try {
            byte[] encoded = json.writeValueAsBytes(body);
            HttpRequest request = request(path).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(encoded)).build();
            return read(request, responseType);
        } catch (JacksonException failure) {
            throw new ExternalRequestEncodingException(failure);
        }
    }

    public <T> Response<T> postForm(String path, ExternalForm body, Class<T> responseType) {
        Objects.requireNonNull(body, "body");
        HttpRequest request = request(path)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body.bytes())).build();
        return read(request, responseType);
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(settings.origin().resolve(path))
                .timeout(settings.deadline())
                .header("Accept", "application/json")
                .header("Accept-Encoding", "identity");
    }

    private <T> Response<T> read(HttpRequest request, Class<T> responseType) {
        Objects.requireNonNull(responseType, "responseType");
        BoundedJsonExchange.JsonResponse reply = exchange.send(request);
        try {
            T value = json.readValue(reply.body(), responseType);
            if (value == null) {
                throw new ExternalHttpRequestFailedException();
            }
            return new Response<>(reply.status(), value);
        } catch (JacksonException failure) {
            throw new ExternalHttpRequestFailedException(failure);
        }
    }

    /** A response may contain tokens. Its diagnostic representation is always redacted. */
    public record Response<T>(int status, T body) {
        @Override
        public String toString() {
            return "ExternalHttpResponse[redacted]";
        }
    }
}
