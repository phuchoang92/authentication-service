package com.vpbank.dcp.auth.adapter.out.keycloak.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Keycloak token endpoint reply to {@code grant_type=password}. Only the ID token is used; access/refresh tokens are dropped. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DirectGrantResponse(@JsonProperty("id_token") String idToken,
                                  @JsonProperty("error") String error) {
    @Override
    public String toString() {
        return "DirectGrantResponse[error=" + error + ", redacted]";
    }
}
