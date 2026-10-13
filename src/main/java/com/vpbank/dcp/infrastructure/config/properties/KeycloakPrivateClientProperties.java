package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.AssertTrue;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth.keycloak.private-client")
public record KeycloakPrivateClientProperties(
        @NotBlank String tokenAudience,
        @NotBlank @DefaultValue("authentication-service") String clientId,
        @NotNull @DefaultValue("PRIVATE_KEY_JWT") KeycloakClientAuthenticationMethod authenticationMethod,
        String clientSecret,
        String privateJwk,
        @Min(1) @Max(8000) long requestTimeoutMs) {

    @AssertTrue(message = "The selected Keycloak client authentication mode requires its credential")
    public boolean isClientCredentialConfigured() {
        if (authenticationMethod == null) {
            return false;
        }
        return switch (authenticationMethod) {
            case CLIENT_SECRET_POST -> clientSecret != null && !clientSecret.isBlank();
            case PRIVATE_KEY_JWT -> privateJwk != null && !privateJwk.isBlank();
        };
    }

    @Override
    public String toString() {
        return "KeycloakPrivateClientProperties[redacted]";
    }
}
