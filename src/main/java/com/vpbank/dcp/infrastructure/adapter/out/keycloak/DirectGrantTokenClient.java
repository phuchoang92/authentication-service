package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.core.port.out.keycloak.KeycloakVerificationUnavailableException;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalForm;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpRequestFailedException;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpSettings;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import tools.jackson.databind.JsonNode;

/**
 * One bounded Direct Grant exchange. No redirect, decompression or automatic retry.
 */
public final class DirectGrantTokenClient {

    private static final String CLIENT_ID = "authentication-service";
    private static final String ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final int MAX_RESPONSE_BYTES = 65_536;

    private final ExternalHttpClient http;
    private final String tokenPath;
    private final PrivateKeyJwtFactory assertions;
    private final Clock clock;

    public DirectGrantTokenClient(HttpClient client, URI endpoint, PrivateKeyJwtFactory assertions,
                                  Duration timeout, Clock clock) {
        URI checked = checkedEndpoint(endpoint);
        this.tokenPath = checked.getRawPath();
        this.assertions = Objects.requireNonNull(assertions, "assertions");
        this.clock = Objects.requireNonNull(clock, "clock");
        ExternalHttpSettings settings = new ExternalHttpSettings(endpoint.resolve("/"),
                timeout, MAX_RESPONSE_BYTES,
                Set.of(ExternalHttpSettings.Route.exact("POST", tokenPath)));
        this.http = new ExternalHttpClient(client, settings);
    }

    public Response verify(PasswordVerification credential) {
        Objects.requireNonNull(credential, "credential");
        ExternalForm form = new ExternalForm()
                .add("grant_type", "password")
                .add("client_id", CLIENT_ID)
                .add("client_assertion_type", ASSERTION_TYPE)
                .add("client_assertion", assertions.issue(clock.instant()))
                .add("scope", "openid")
                .add("username", credential.username())
                .add("password", credential.password());
        try {
            ExternalHttpClient.Response<JsonNode> response = http.postForm(
                    tokenPath, form, JsonNode.class);
            JsonNode body = response.body();
            if (!body.isObject()) {
                throw new KeycloakVerificationUnavailableException();
            }
            return new Response(response.status(), stringField(body, "error"),
                    stringField(body, "id_token"));
        } catch (ExternalHttpRequestFailedException failure) {
            throw new KeycloakVerificationUnavailableException(failure);
        }
    }

    private static String stringField(JsonNode body, String name) {
        JsonNode field = body.path(name);
        return field.isString() ? field.asString() : null;
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

    public record Response(int status, String errorCode, String identityToken) {
        @Override
        public String toString() {
            return "DirectGrantResponse[redacted]";
        }
    }
}
