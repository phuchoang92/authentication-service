package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth.customer")
public record CustomerLoginEligibilityProperties(@Positive long statusMaxAgeMs) { }
