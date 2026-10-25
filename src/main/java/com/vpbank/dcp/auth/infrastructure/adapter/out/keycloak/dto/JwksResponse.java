package com.vpbank.dcp.auth.infrastructure.adapter.out.keycloak.dto;

/** The realm's JWKS document as text; Nimbus parses it. */
public record JwksResponse(String json) { }
