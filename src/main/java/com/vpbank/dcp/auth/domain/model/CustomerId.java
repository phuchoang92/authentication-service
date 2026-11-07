package com.vpbank.dcp.auth.domain.model;

import java.util.regex.Pattern;
import lombok.NonNull;

/** Customer number as the Customer service issues it: 1–16 letters or digits. */
public record CustomerId(@NonNull String value) {
    private static final Pattern FORMAT = Pattern.compile("[A-Za-z0-9]{1,16}");

    public CustomerId {
        if (!FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("Customer ID has an invalid format");
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
