package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalForm;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalEndpoint;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import java.util.Objects;
import tools.jackson.databind.JsonNode;

/**
 * Sends one Direct Grant request. Response interpretation belongs to the adapter mapper.
 */
public final class DirectGrantTokenClient {

    private final ExternalHttpClient http;
    private final ExternalEndpoint<JsonNode, JsonNode> tokenEndpoint;
    private final KeycloakClientAuthentication authentication;

    public DirectGrantTokenClient(ExternalHttpClient http,
                                  ExternalEndpoint<JsonNode, JsonNode> tokenEndpoint,
                                  KeycloakClientAuthentication authentication) {
        this.http = Objects.requireNonNull(http, "http");
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
        this.authentication = Objects.requireNonNull(authentication, "authentication");
    }

    public ExternalHttpClient.Response<JsonNode, JsonNode> requestTokens(String username,
                                                                         String password) {
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(password, "password");
        ExternalForm form = new ExternalForm()
                .add("grant_type", "password")
                .add("scope", "openid")
                .add("username", username)
                .add("password", password);
        authentication.addCredentials(form);
        return http.postForm(tokenEndpoint, form);
    }
}
