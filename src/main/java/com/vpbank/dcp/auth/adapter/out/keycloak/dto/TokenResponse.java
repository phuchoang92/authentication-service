package com.vpbank.dcp.auth.adapter.out.keycloak.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Keycloak token endpoint body (snake_case on the wire). */
public record TokenResponse(@JsonProperty("access_token") String accessToken) { }
