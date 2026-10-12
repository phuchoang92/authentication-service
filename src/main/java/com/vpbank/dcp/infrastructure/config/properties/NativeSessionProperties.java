package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth.native-session")
public record NativeSessionProperties(@NotBlank String lookupKeyVersion,
                                      @NotBlank String lookupHmacBase64,
                                      @Positive long nonceValidityMs,
                                      boolean integrationActivationEnabled) { }
