package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.core.port.out.keycloak.KeycloakVerificationUnavailableException;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerificationOutcome;
import java.util.Objects;

/** Discards Keycloak OAuth tokens after verifying the ID token; never returns them to App. */
public final class HttpDirectGrantPasswordVerifier implements DirectGrantPasswordVerifier {

    private final DirectGrantTokenClient client;
    private final KeycloakIdTokenVerifier idTokens;

    public HttpDirectGrantPasswordVerifier(DirectGrantTokenClient client,
                                           KeycloakIdTokenVerifier idTokens) {
        this.client = Objects.requireNonNull(client, "client");
        this.idTokens = Objects.requireNonNull(idTokens, "idTokens");
    }

    @Override
    public PasswordVerificationOutcome verify(PasswordVerification credential) {
        DirectGrantTokenClient.Response response = client.verify(credential);
        if (response.status() == 400 && "invalid_grant".equals(response.errorCode())) {
            return new PasswordVerificationOutcome.Rejected();
        }
        if (response.status() != 200) {
            throw new KeycloakVerificationUnavailableException();
        }
        if (response.identityToken() == null || response.identityToken().isBlank()) {
            throw new KeycloakVerificationUnavailableException();
        }
        return new PasswordVerificationOutcome.Verified(idTokens.verify(response.identityToken()));
    }
}
