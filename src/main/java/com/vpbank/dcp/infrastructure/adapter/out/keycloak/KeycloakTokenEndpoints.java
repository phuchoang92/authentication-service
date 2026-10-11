package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalEndpoint;
import java.net.URI;
import java.util.Objects;
import java.util.Set;
import tools.jackson.databind.JsonNode;

/** Defines the single Keycloak token route and its success/error response types. */
public final class KeycloakTokenEndpoints {

    private KeycloakTokenEndpoints() {
    }

    public static ExternalEndpoint<JsonNode, JsonNode> directGrant(URI endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        if (!"https".equals(endpoint.getScheme()) || endpoint.getHost() == null
                || endpoint.getUserInfo() != null || endpoint.getRawQuery() != null
                || endpoint.getRawFragment() != null || !endpoint.getPath().matches(
                "/realms/[A-Za-z0-9._-]+/protocol/openid-connect/token")) {
            throw new InvalidKeycloakClientConfigurationException();
        }
        return ExternalEndpoint.postForm(endpoint.getRawPath(), JsonNode.class, Set.of(200),
                JsonNode.class, Set.of(400));
    }
}
