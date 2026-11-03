package com.vpbank.dcp.auth.application.service;

import java.time.Duration;
import java.util.Objects;

/**
 * How Auth names itself and the BFF in a service token, and how long a token lives. Plain Java, built by
 * configuration from validated properties (bounds are checked there).
 */
public record ServiceTokenSettings(String issuer, String audience, Duration lifetime) {
    public ServiceTokenSettings {
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(audience, "audience");
        Objects.requireNonNull(lifetime, "lifetime");
        if (issuer.isBlank() || audience.isBlank() || lifetime.isNegative() || lifetime.isZero()) {
            throw new IllegalArgumentException("Service token settings need an issuer, an audience and a positive lifetime");
        }
    }
}
