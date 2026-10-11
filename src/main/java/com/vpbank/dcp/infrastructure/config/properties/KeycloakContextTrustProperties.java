package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Pinned verification authority; never populated from a received context header.
 */
@Validated
@ConfigurationProperties(prefix = "auth.keycloak.context-trust")
public record KeycloakContextTrustProperties(
        @NotBlank String issuer, @NotBlank String keyId, @NotBlank String publicJwk) {
}
