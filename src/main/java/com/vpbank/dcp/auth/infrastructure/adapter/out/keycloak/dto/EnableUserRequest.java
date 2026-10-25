package com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.dto;

/** Keycloak Admin {@code PUT /users/{id}} body with only the flag we change. */
public record EnableUserRequest(boolean enabled) { }
