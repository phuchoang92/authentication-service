package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.core.port.out.keycloak.KeycloakVerificationUnavailableException;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.infrastructure.adapter.out.http.BoundedJsonExchange;
import com.vpbank.dcp.infrastructure.adapter.out.http.PartnerHttpFailureException;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/**
 * One bounded Direct Grant exchange. No redirect, decompression or automatic retry.
 */
public final class DirectGrantTokenClient {

    private static final String CLIENT_ID = "authentication-service";
    private static final String ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final int MAX_RESPONSE_BYTES = 65_536;

    private final BoundedJsonExchange exchange;
    private final URI endpoint;
    private final PrivateKeyJwtFactory assertions;
    private final Duration timeout;
    private final Clock clock;

    public DirectGrantTokenClient(HttpClient client, URI endpoint, PrivateKeyJwtFactory assertions,
                                  Duration timeout, Clock clock) {
        this.endpoint = checkedEndpoint(endpoint);
        this.assertions = Objects.requireNonNull(assertions, "assertions");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (timeout.isZero() || timeout.isNegative()) {
            throw new InvalidKeycloakClientConfigurationException();
        }
        this.exchange = new BoundedJsonExchange(client, endpoint.resolve("/"), timeout,
                MAX_RESPONSE_BYTES, Set.of(BoundedJsonExchange.AllowedEndpoint.exact(
                        "POST", endpoint.getRawPath())));
    }

    public Response verify(PasswordVerification credential) {
        Objects.requireNonNull(credential, "credential");
        String form = field("grant_type", "password")
                + "&" + field("client_id", CLIENT_ID)
                + "&" + field("client_assertion_type", ASSERTION_TYPE)
                + "&" + field("client_assertion", assertions.issue(clock.instant()))
                + "&" + field("scope", "openid")
                + "&" + field("username", credential.username())
                + "&" + field("password", credential.password());
        HttpRequest request = HttpRequest.newBuilder(endpoint)
                .timeout(timeout)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .header("Accept-Encoding", "identity")
                .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                .build();
        try {
            BoundedJsonExchange.JsonResponse response = exchange.send(request);
            return new Response(response.status(), response.body());
        } catch (PartnerHttpFailureException failure) {
            throw new KeycloakVerificationUnavailableException(failure);
        }
    }

    private static URI checkedEndpoint(URI endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        if (!"https".equals(endpoint.getScheme()) || endpoint.getHost() == null
                || endpoint.getUserInfo() != null || endpoint.getRawQuery() != null
                || endpoint.getRawFragment() != null || !endpoint.getPath().matches(
                "/realms/[A-Za-z0-9._-]+/protocol/openid-connect/token")) {
            throw new InvalidKeycloakClientConfigurationException();
        }
        return endpoint;
    }

    private static String field(String name, String value) {
        return URLEncoder.encode(name, StandardCharsets.UTF_8) + "="
                + URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    public record Response(int status, String body) {
        @Override
        public String toString() {
            return "DirectGrantResponse[redacted]";
        }
    }
}
