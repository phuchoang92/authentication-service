package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth.token-delivery")
public record BankingTokenDeliveryProperties(@NotBlank String issuer,
                                             @NotBlank String receiptPrivateJwk) {

    @Override
    public String toString() {
        return "BankingTokenDeliveryProperties[redacted]";
    }
}
