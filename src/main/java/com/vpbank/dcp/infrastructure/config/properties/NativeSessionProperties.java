package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth.native-session")
public record NativeSessionProperties(@Positive long nonceValidityMs,
                                      boolean integrationActivationEnabled) { }
