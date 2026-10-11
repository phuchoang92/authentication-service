package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalForm;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalEndpoint;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import java.time.Clock;
import java.util.Objects;
import tools.jackson.databind.JsonNode;

/**
 * Sends one Direct Grant request. Response interpretation belongs to the adapter mapper.
 */
public final class DirectGrantTokenClient {

    private static final String CLIENT_ID = "authentication-service";
    private static final String ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private final ExternalHttpClient http;
    private final ExternalEndpoint<JsonNode, JsonNode> tokenEndpoint;
    private final PrivateKeyJwtFactory assertions;
    private final Clock clock;

    public DirectGrantTokenClient(ExternalHttpClient http,
                                  ExternalEndpoint<JsonNode, JsonNode> tokenEndpoint,
                                  PrivateKeyJwtFactory assertions, Clock clock) {
        this.http = Objects.requireNonNull(http, "http");
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
        this.assertions = Objects.requireNonNull(assertions, "assertions");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public ExternalHttpClient.Response<JsonNode, JsonNode> requestTokens(String username,
                                                                         String password) {
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(password, "password");
        ExternalForm form = new ExternalForm()
                .add("grant_type", "password")
                .add("client_id", CLIENT_ID)
                .add("client_assertion_type", ASSERTION_TYPE)
                .add("client_assertion", assertions.issue(clock.instant()))
                .add("scope", "openid")
                .add("username", username)
                .add("password", password);
        return http.postForm(tokenEndpoint, form);
    }
}
