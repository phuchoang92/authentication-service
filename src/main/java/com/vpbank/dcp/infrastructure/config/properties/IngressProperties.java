package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Set;

@Validated
@ConfigurationProperties(prefix = "auth.ingress")
public record IngressProperties(@NotBlank String externalOrigin, @NotEmpty Set<String> allowedWorkloadUris) {

    public IngressProperties {
        allowedWorkloadUris = allowedWorkloadUris == null ? null : Set.copyOf(allowedWorkloadUris);
    }
}
