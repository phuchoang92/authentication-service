package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth.keycloak.id-token-trust")
public record KeycloakIdTokenTrustProperties(@NotBlank String issuer,
                                             @NotBlank String keyId,
                                             @NotBlank String publicJwk) {

    @Override
    public String toString() {
        return "KeycloakIdTokenTrustProperties[redacted]";
    }
}
