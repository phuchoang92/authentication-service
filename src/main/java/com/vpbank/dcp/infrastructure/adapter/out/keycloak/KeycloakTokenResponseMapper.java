package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.core.password.PasswordVerifierUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import tools.jackson.databind.JsonNode;

/** Validates the selected Direct Grant fields without exposing OAuth tokens to core. */
final class KeycloakTokenResponseMapper {

    private KeycloakTokenResponseMapper() {
    }

    static String requireIdentityToken(ExternalHttpClient.Response<JsonNode, JsonNode> response) {
        JsonNode body = response.successBody();
        JsonNode identityToken = body.path("id_token");
        if (!body.isObject() || !identityToken.isString() || identityToken.asString().isBlank()) {
            throw new PasswordVerifierUnavailableException();
        }
        return identityToken.asString();
    }

    static boolean isInvalidGrant(ExternalHttpClient.Response<JsonNode, JsonNode> response) {
        JsonNode errorBody = response.errorBody();
        JsonNode errorCode = errorBody.path("error");
        if (!errorBody.isObject() || !errorCode.isString()) {
            throw new PasswordVerifierUnavailableException();
        }
        return response.status() == 400 && "invalid_grant".equals(errorCode.asString());
    }
}
