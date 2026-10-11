package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth.password-flow")
public record PasswordFlowProperties(@NotBlank String commandKeyId,
                                     @NotBlank String commandHmacBase64,
                                     @NotBlank String customerPolicyVersion,
                                     @Positive long customerStatusMaxAgeMs,
                                     @Positive long credentialDeadlineMs,
                                     @Positive long journeyDeadlineMs) { }
