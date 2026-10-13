package com.vpbank.dcp.infrastructure.adapter.out.keycloak;

import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalForm;

/** Supplies credentials for the configured confidential client, selected at startup. */
public interface KeycloakClientAuthentication {

    void addCredentials(ExternalForm form);
}
