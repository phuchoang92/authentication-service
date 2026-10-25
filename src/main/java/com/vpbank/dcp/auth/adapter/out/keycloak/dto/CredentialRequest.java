package com.vpbank.dcp.auth.adapter.out.keycloak.dto;

/** Keycloak Admin {@code PUT /users/{id}/reset-password} body. */
public record CredentialRequest(String type, String value, boolean temporary) {
    @Override
    public String toString() {
        return "CredentialRequest[type=" + type + ", redacted]";
    }
}
