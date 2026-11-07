package com.vpbank.dcp.auth.application.service;

import java.time.Duration;
import lombok.NonNull;

/**
 * How Auth names itself and the BFF in a service token, and how long a token lives. Plain Java, built by
 * configuration from validated properties (bounds are checked there).
 */
public record ServiceTokenSettings(@NonNull String issuer, @NonNull String audience, @NonNull Duration lifetime) {
    public ServiceTokenSettings {
        if (issuer.isBlank() || audience.isBlank() || lifetime.isNegative() || lifetime.isZero()) {
            throw new IllegalArgumentException("Service token settings need an issuer, an audience and a positive lifetime");
        }
    }
}
