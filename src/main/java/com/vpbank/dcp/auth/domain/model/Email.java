package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;
import java.util.regex.Pattern;

/** E-mail address, at most 255 characters. Addresses compare case-insensitively. */
public record Email(String value) {
    private static final Pattern FORMAT = Pattern.compile("[^\\s@]+@[^\\s@]+\\.[^\\s@]+");

    public Email {
        Objects.requireNonNull(value, "value");
        if (value.length() > 255 || !FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("Email has an invalid format");
        }
    }

    public boolean sameAs(String other) {
        return other != null && value.equalsIgnoreCase(other);
    }

    /** Personal data: never printed. */
    @Override
    public String toString() {
        return "Email[redacted]";
    }
}
