package com.vpbank.dcp.auth.infrastructure.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.hibernate.validator.constraints.time.DurationMax;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Service token settings (slice 12); read only when {@code auth.service-token.enabled=true}. The lifetime is a
 * policy value: no default, 1 to 30 minutes. {@code signingPrivateJwk} is the private P-256 JWK (text, with
 * {@code kid}) the tokens are signed with; each caller has its pinned public JWK (with {@code kid}) and the
 * scopes it may ask for. {@code toString} hides every key.
 */
@Validated
@ConfigurationProperties(prefix = "auth.service-token")
public record ServiceTokenProperties(
        boolean enabled,
        @NotBlank @DefaultValue("authentication-service") String issuer,
        @NotBlank @DefaultValue("mobile-bff") String audience,
        @NotNull @DurationMin(minutes = 1) @DurationMax(minutes = 30) Duration lifetime,
        @NotBlank String signingPrivateJwk,
        @Valid @NotEmpty Map<String, Caller> callers) {

    public record Caller(@NotBlank String publicJwk, @NotEmpty List<String> scopes) {
        @Override
        public String toString() {
            return "Caller[scopes=" + scopes + "]";
        }
    }

    @Override
    public String toString() {
        return "ServiceTokenProperties[enabled=" + enabled + ", issuer=" + issuer + ", audience=" + audience
                + ", lifetime=" + lifetime + ", callers=" + callers + "]";
    }
}
