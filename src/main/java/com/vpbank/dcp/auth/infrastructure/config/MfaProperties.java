package com.vpbank.dcp.auth.infrastructure.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/** The MFA service (DD 20 §5): origin, timeout, the pinned ES256 receipt key (public JWK text) and its issuer. */
@Validated
@ConfigurationProperties(prefix = "auth.mfa")
public record MfaProperties(@NotBlank String origin,
                            @NotNull @DefaultValue("PT3S") Duration timeout,
                            @NotBlank String receiptIssuer,
                            @NotBlank String receiptPublicJwk) {
    @Override
    public String toString() {
        return "MfaProperties[origin=" + origin + ", receiptIssuer=" + receiptIssuer + "]";
    }
}
