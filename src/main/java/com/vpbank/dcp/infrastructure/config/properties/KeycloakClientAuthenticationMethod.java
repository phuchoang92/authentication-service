package com.vpbank.dcp.infrastructure.config.properties;

/** Supported token-endpoint client authentication modes; unknown configuration fails binding. */
public enum KeycloakClientAuthenticationMethod {
    PRIVATE_KEY_JWT,
    CLIENT_SECRET_POST
}
