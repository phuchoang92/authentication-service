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

    public <S, E> Response<S, E> getJson(ExternalEndpoint<S, E> endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        endpoint.requireKind(ExternalEndpoint.Kind.GET_JSON);
        return read(request(endpoint.path()).GET().build(), endpoint);
    }

    public <S, E> Response<S, E> postJson(ExternalEndpoint<S, E> endpoint, Object body) {
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

    public <S, E> Response<S, E> postForm(ExternalEndpoint<S, E> endpoint, ExternalForm body) {
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

    private <S, E> Response<S, E> read(HttpRequest request, ExternalEndpoint<S, E> endpoint) {
        BoundedJsonExchange.JsonResponse reply = exchange.send(request);
        boolean success = endpoint.acceptsSuccess(reply.status());
        boolean error = endpoint.acceptsError(reply.status());
        if (!success && !error) {
            throw new ExternalHttpRequestFailedException(reply.status());
        }
        try {
            if (success) {
                S value = json.readValue(reply.body(), endpoint.successType());
                if (value == null) {
                    throw new ExternalHttpRequestFailedException();
                }
                return Response.success(reply.status(), value);
            }
            E value = json.readValue(reply.body(), endpoint.errorType());
            if (value == null) {
                throw new ExternalHttpRequestFailedException();
            }
            return Response.error(reply.status(), value);
        } catch (JacksonException failure) {
            throw new ExternalHttpRequestFailedException(failure);
        }
    }

    /**
     * A response may contain tokens or provider error details. Only one body is present.
     */
    public static final class Response<S, E> {
        private final int status;
        private final S successBody;
        private final E errorBody;

        private Response(int status, S successBody, E errorBody) {
            this.status = status;
            this.successBody = successBody;
            this.errorBody = errorBody;
        }

        private static <S, E> Response<S, E> success(int status, S body) {
            return new Response<>(status, body, null);
        }

        private static <S, E> Response<S, E> error(int status, E body) {
            return new Response<>(status, null, body);
        }

        public int status() {
            return status;
        }

        public boolean isSuccess() {
            return successBody != null;
        }

        public S successBody() {
            if (!isSuccess()) {
                throw new IllegalStateException("Response is not a success");
            }
            return successBody;
        }

        public E errorBody() {
            if (isSuccess()) {
                throw new IllegalStateException("Response is not an error");
            }
            return errorBody;
        }

        @Override
        public String toString() {
            return "ExternalHttpResponse[redacted]";
        }
    }
}
