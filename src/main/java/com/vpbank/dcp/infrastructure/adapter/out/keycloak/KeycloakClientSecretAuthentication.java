package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalForm;

/** OAuth client_secret_post; credentials travel in the redacted HTTPS form body. */
public final class KeycloakClientSecretAuthentication implements KeycloakClientAuthentication {

    private final String clientId;
    private final String clientSecret;

    public KeycloakClientSecretAuthentication(String clientId, String clientSecret) {
        if (clientId == null || clientId.isBlank() || clientSecret == null || clientSecret.isBlank()) {
            throw new InvalidKeycloakClientConfigurationException();
        }
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    @Override
    public void addCredentials(ExternalForm form) {
        form.add("client_id", clientId).add("client_secret", clientSecret);
    }

    @Override
    public String toString() {
        return "KeycloakClientSecretAuthentication[redacted]";
    }
}
