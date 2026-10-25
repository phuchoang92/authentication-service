package com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.constant;

/**
 * Keycloak paths shared by the admin, Direct Grant and JWKS adapters. Each is a {@code RestClient}
 * URI template; {@code {realm}} and {@code {id}} are bound at the call site.
 */
public final class KeycloakEndpoints {
    public static final String TOKEN = "/realms/{realm}/protocol/openid-connect/token";
    public static final String JWKS = "/realms/{realm}/protocol/openid-connect/certs";
    public static final String ADMIN_USERS = "/admin/realms/{realm}/users";
    public static final String ADMIN_USER = "/admin/realms/{realm}/users/{id}";
    public static final String ADMIN_USER_RESET_PASSWORD = "/admin/realms/{realm}/users/{id}/reset-password";

    private KeycloakEndpoints() {
    }
}
