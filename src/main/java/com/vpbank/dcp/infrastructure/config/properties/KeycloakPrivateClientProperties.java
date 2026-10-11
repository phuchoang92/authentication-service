package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth.keycloak.private-client")
public record KeycloakPrivateClientProperties(
        @NotBlank String tokenAudience,
        @NotBlank String privateJwk,
        @Min(1) @Max(8000) long requestTimeoutMs) {

    @Override
    public String toString() {
        return "KeycloakPrivateClientProperties[redacted]";
    }
}
