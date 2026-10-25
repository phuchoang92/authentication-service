package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.core.password.PasswordVerifier;
import com.vpbank.dcp.core.password.PasswordVerifierUnavailableException;
import com.vpbank.dcp.core.password.PasswordVerification;
import com.vpbank.dcp.core.password.PasswordVerificationOutcome;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpRequestFailedException;
import java.util.Objects;
import tools.jackson.databind.JsonNode;

/** Discards Keycloak OAuth tokens after verifying the ID token; never returns them to App. */
public final class KeycloakDirectGrantPasswordVerifier implements PasswordVerifier {

    private final DirectGrantTokenClient client;
    private final KeycloakIdTokenVerifier idTokens;

    public KeycloakDirectGrantPasswordVerifier(DirectGrantTokenClient client,
                                           KeycloakIdTokenVerifier idTokens) {
        this.client = Objects.requireNonNull(client, "client");
        this.idTokens = Objects.requireNonNull(idTokens, "idTokens");
    }

    @Override
    public PasswordVerificationOutcome verify(PasswordVerification credential) {
        ExternalHttpClient.Response<JsonNode, JsonNode> response;
        try {
            response = client.requestTokens(credential.username(), credential.password());
        } catch (ExternalHttpRequestFailedException failure) {
            throw new PasswordVerifierUnavailableException(failure);
        }
        if (!response.isSuccess()) {
            if (KeycloakTokenResponseMapper.isInvalidGrant(response)) {
                return new PasswordVerificationOutcome.Rejected();
            }
            throw new PasswordVerifierUnavailableException();
        }
        String identityToken = KeycloakTokenResponseMapper.requireIdentityToken(response);
        return new PasswordVerificationOutcome.Verified(idTokens.verify(identityToken));
    }
}
