package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth.customer-context-signing")
public record CustomerContextSigningProperties(@NotBlank String issuer,
                                               @NotBlank String privateJwk) { }
