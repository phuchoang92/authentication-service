package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * The business journey a service token belongs to, such as an onboarding request ID. Opaque to Auth: it is
 * copied into the token's {@code businessReference} claim so the BFF and the owning service can bind the token
 * to that one journey. 1–128 URL-safe characters.
 */
public record BusinessReference(String value) {
    private static final Pattern FORMAT = Pattern.compile("[A-Za-z0-9._:-]{1,128}");

    public BusinessReference {
        Objects.requireNonNull(value, "value");
        if (!FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("Business reference has an invalid format");
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
