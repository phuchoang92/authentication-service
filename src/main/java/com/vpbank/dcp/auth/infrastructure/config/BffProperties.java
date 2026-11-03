package com.vpbank.dcp.auth.infrastructure.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * The BFF as the caller of the trusted-device routes (slice 11, DD 20 §6a): the issuer its assertions name and
 * the pinned public P-256 JWK (text, with {@code kid}) they are signed with. No default: without them the routes
 * would admit nobody, so the application does not start.
 */
@Validated
@ConfigurationProperties(prefix = "auth.bff")
public record BffProperties(@NotBlank String assertionIssuer,
                            @NotBlank String assertionPublicJwk) {
    @Override
    public String toString() {
        return "BffProperties[assertionIssuer=" + assertionIssuer + "]";
    }
}
