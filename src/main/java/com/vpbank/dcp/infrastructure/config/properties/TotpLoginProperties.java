package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth.totp-login")
public record TotpLoginProperties(@NotBlank String secretKeyId,
                                  @NotBlank String secretKeyBase64,
                                  @NotBlank String proofPrivateJwk,
                                  @Positive long challengeLifetimeSeconds,
                                  @Positive int maximumFailures,
                                  @Positive long lockMinutes) {
    @Override
    public String toString() {
        return "TotpLoginProperties[redacted]";
    }
}
