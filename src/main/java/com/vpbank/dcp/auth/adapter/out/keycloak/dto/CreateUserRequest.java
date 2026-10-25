package com.vpbank.dcp.auth.adapter.out.keycloak.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

import java.util.List;

/** Keycloak Admin {@code POST /users} body. Null fields (no e-mail) are left out of the JSON. */
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CreateUserRequest(String username, String firstName, String lastName, String email,
                                Boolean emailVerified, boolean enabled, List<String> requiredActions) {
    @Override
    public String toString() {
        return "CreateUserRequest[username=" + username + ", redacted]";
    }
}
