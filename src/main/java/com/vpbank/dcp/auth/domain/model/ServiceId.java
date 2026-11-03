package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * The name of an internal service that calls Auth, as its client assertion and the issued token's {@code sub}
 * carry it: 3–64 lower-case letters, digits or hyphens, such as {@code onboarding-service}.
 */
public record ServiceId(String value) {
    private static final Pattern FORMAT = Pattern.compile("[a-z0-9-]{3,64}");

    public ServiceId {
        Objects.requireNonNull(value, "value");
        if (!FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("Service ID has an invalid format");
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
