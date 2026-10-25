package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Login name chosen at onboarding: 3–64 letters, digits, dot, underscore or dash. The database
 * compares it case-insensitively, so {@link #sameAs} does too.
 */
public record UserName(String value) {
    private static final Pattern FORMAT = Pattern.compile("[A-Za-z0-9._-]{3,64}");

    public UserName {
        Objects.requireNonNull(value, "value");
        if (!FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("User name has an invalid format");
        }
    }

    public boolean sameAs(UserName other) {
        return other != null && value.equalsIgnoreCase(other.value);
    }

    @Override
    public String toString() {
        return value;
    }
}
