package com.vpbank.dcp.infrastructure.adapter.out.http;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.*;
import java.util.regex.Pattern;

/**
 * Shared transport mechanics only. Each external-service adapter owns its endpoint patterns,
 * request DTOs, response interpretation, and retry/reconciliation policy.
 */
public final class BoundedJsonExchange {

    private final HttpClient client;
    private final URI origin;
    private final Duration deadline;
    private final int maximumResponseBytes;
    private final Set<AllowedEndpoint> endpoints;

    public BoundedJsonExchange(HttpClient client, URI origin, Duration deadline,
                               int maximumResponseBytes, Set<AllowedEndpoint> endpoints) {
        this.client = Objects.requireNonNull(client, "client");
        this.origin = Objects.requireNonNull(origin, "origin");
        this.deadline = Objects.requireNonNull(deadline, "deadline");
        this.endpoints = Set.copyOf(endpoints);
        this.maximumResponseBytes = maximumResponseBytes;
        if (client.followRedirects() != HttpClient.Redirect.NEVER
                || !"https".equals(origin.getScheme()) || origin.getHost() == null
                || origin.getUserInfo() != null || origin.getRawQuery() != null
                || origin.getRawFragment() != null
                || !(origin.getRawPath().isEmpty() || "/".equals(origin.getRawPath()))
                || deadline.isNegative() || deadline.isZero()
                || maximumResponseBytes < 1 || this.endpoints.isEmpty()) {
            throw new InvalidExternalHttpSettingsException();
        }
    }

    public JsonResponse send(HttpRequest request) {
        Objects.requireNonNull(request, "request");
        if (!allowed(request)) {
            throw new ExternalHttpRequestFailedException();
        }
        CompletableFuture<HttpResponse<byte[]>> exchange;
        try {
            exchange = client.sendAsync(request,
                    ignored -> new LimitedBodySubscriber(maximumResponseBytes));
        } catch (IllegalArgumentException | SecurityException | RejectedExecutionException failure) {
            throw new ExternalHttpRequestFailedException(failure);
        }
        try {
            HttpResponse<byte[]> response = exchange.get(deadline.toNanos(), TimeUnit.NANOSECONDS);
            if (response.headers().firstValue("Content-Encoding").isPresent()
                    || response.headers().firstValue("Content-Type")
                    .map(value -> !value.toLowerCase(java.util.Locale.ROOT)
                            .matches("application/json(?:\\s*;.*)?"))
                    .orElse(true)) {
                throw new ExternalHttpRequestFailedException();
            }
            String body = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(response.body())).toString();
            return new JsonResponse(response.statusCode(), body);
        } catch (InterruptedException failure) {
            exchange.cancel(true);
            Thread.currentThread().interrupt();
            throw new ExternalHttpRequestFailedException(failure);
        } catch (TimeoutException failure) {
            exchange.cancel(true);
            throw new ExternalHttpRequestFailedException(failure);
        } catch (ExecutionException failure) {
            exchange.cancel(true);
            throw new ExternalHttpRequestFailedException(failure.getCause());
        } catch (CharacterCodingException failure) {
            throw new ExternalHttpRequestFailedException(failure);
        }
    }

    private boolean allowed(HttpRequest request) {
        URI target = request.uri();
        String path = target.getRawPath();
        if (!Objects.equals(origin.getScheme(), target.getScheme())
                || !Objects.equals(origin.getHost(), target.getHost())
                || origin.getPort() != target.getPort()
                || target.getUserInfo() != null || target.getRawQuery() != null
                || target.getRawFragment() != null || path == null
                || path.contains("//") || path.contains("\\")
                || path.matches("(?i).*%(?:2e|2f|5c).*")) {
            return false;
        }
        for (String segment : path.split("/")) {
            if (".".equals(segment) || "..".equals(segment)) {
                return false;
            }
        }
        return endpoints.stream().anyMatch(endpoint -> endpoint.allows(request.method(), path));
    }

    public record AllowedEndpoint(String method, Pattern path) {
        public AllowedEndpoint {
            Objects.requireNonNull(method, "method");
            Objects.requireNonNull(path, "path");
            if (!method.matches("[A-Z]+")) {
                throw new InvalidExternalHttpSettingsException();
            }
        }

        public static AllowedEndpoint exact(String method, String path) {
            return new AllowedEndpoint(method, Pattern.compile(Pattern.quote(path)));
        }

        public boolean allows(String requestMethod, String requestPath) {
            return method.equals(requestMethod) && path.matcher(requestPath).matches();
        }
    }

    /**
     * OAuth bodies can contain tokens; never include the body in diagnostics.
     */
    public static final class JsonResponse {
        private final int status;
        private final String body;

        private JsonResponse(int status, String body) {
            this.status = status;
            this.body = body;
        }

        public int status() {
            return status;
        }

        public String body() {
            return body;
        }

        @Override
        public String toString() {
            return "JsonResponse[redacted]";
        }
    }

}
