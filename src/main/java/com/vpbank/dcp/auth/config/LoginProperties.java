package com.vpbank.dcp.auth.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/** Login settings; read only when {@code auth.login.enabled=true}. */
@Validated
@ConfigurationProperties(prefix = "auth.login")
public record LoginProperties(boolean enabled, @Valid @NotNull Keycloak keycloak) {

    /** Direct Grant client. The issuer is {@code <baseUrl>/realms/<realm>} and must match the stored identity. */
    public record Keycloak(@NotBlank String baseUrl,
                           @NotBlank String realm,
                           @NotBlank String clientId,
                           @NotBlank String clientSecret,
                           @NotNull @DefaultValue("PT3S") Duration timeout) {
        public String issuer() {
            return baseUrl.replaceAll("/+$", "") + "/realms/" + realm;
        }

        @Override
        public String toString() {
            return "Keycloak[baseUrl=" + baseUrl + ", realm=" + realm + ", clientId=" + clientId + "]";
        }
    }

    @Override
    public String toString() {
        return "LoginProperties[enabled=" + enabled + ", " + keycloak + "]";
    }
}
