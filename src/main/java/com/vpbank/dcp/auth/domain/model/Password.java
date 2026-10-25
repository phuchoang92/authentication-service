package com.vpbank.dcp.auth.domain.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * A password in transit to the identity provider. Never stored, compared or printed here;
 * {@link #clear()} wipes it once the verification call has been made.
 */
public final class Password {
    private final char[] value;

    public Password(char[] value) {
        Objects.requireNonNull(value, "value");
        if (value.length == 0) {
            throw new IllegalArgumentException("Password must not be empty");
        }
        this.value = value.clone();
    }

    public char[] value() {
        return value.clone();
    }

    public void clear() {
        Arrays.fill(value, '\0');
    }

    @Override
    public String toString() {
        return "Password[redacted]";
    }
}
