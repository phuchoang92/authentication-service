package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;
import java.util.regex.Pattern;

/** Customer number as the Customer service issues it: 1–16 letters or digits. */
public record CustomerId(String value) {
    private static final Pattern FORMAT = Pattern.compile("[A-Za-z0-9]{1,16}");

    public CustomerId {
        Objects.requireNonNull(value, "value");
        if (!FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("Customer ID has an invalid format");
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
