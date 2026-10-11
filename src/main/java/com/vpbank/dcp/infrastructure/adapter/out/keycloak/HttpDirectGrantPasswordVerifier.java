package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.core.port.out.keycloak.KeycloakVerificationUnavailableException;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerificationOutcome;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import java.util.Objects;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Discards Keycloak OAuth tokens after verifying the ID token; never returns them to App. */
public final class HttpDirectGrantPasswordVerifier implements DirectGrantPasswordVerifier {

    private final DirectGrantTokenClient client;
    private final KeycloakIdTokenVerifier idTokens;
    private final StrictJoseJson strictJson;
    private final JsonMapper json;

    public HttpDirectGrantPasswordVerifier(DirectGrantTokenClient client,
                                           KeycloakIdTokenVerifier idTokens,
                                           StrictJoseJson strictJson, JsonMapper json) {
        this.client = Objects.requireNonNull(client, "client");
        this.idTokens = Objects.requireNonNull(idTokens, "idTokens");
        this.strictJson = Objects.requireNonNull(strictJson, "strictJson");
        this.json = Objects.requireNonNull(json, "json");
    }

    @Override
    public PasswordVerificationOutcome verify(PasswordVerification credential) {
        DirectGrantTokenClient.Response response = client.verify(credential);
        strictJson.checkJson(response.body());
        try {
            JsonNode body = json.readTree(response.body());
            if (response.status() == 400 && "invalid_grant".equals(
                    body.path("error").asText())) {
                return new PasswordVerificationOutcome.Rejected();
            }
            if (response.status() != 200) {
                throw new KeycloakVerificationUnavailableException();
            }
            JsonNode identityToken = body.path("id_token");
            if (!identityToken.isString() || identityToken.asString().isBlank()) {
                throw new KeycloakVerificationUnavailableException();
            }
            return new PasswordVerificationOutcome.Verified(idTokens.verify(identityToken.asString()));
        } catch (RuntimeException failure) {
            if (failure instanceof KeycloakVerificationUnavailableException unavailable) {
                throw unavailable;
            }
            throw new KeycloakVerificationUnavailableException(failure);
        }
    }
}
