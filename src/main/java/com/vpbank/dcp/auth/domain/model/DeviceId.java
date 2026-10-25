package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;
import java.util.regex.Pattern;

/** Opaque device identifier the app sends; 1–64 URL-safe characters. Trust rules come in slice 3. */
public record DeviceId(String value) {
    private static final Pattern FORMAT = Pattern.compile("[A-Za-z0-9._-]{1,64}");

    public DeviceId {
        Objects.requireNonNull(value, "value");
        if (!FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("Device ID has an invalid format");
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
