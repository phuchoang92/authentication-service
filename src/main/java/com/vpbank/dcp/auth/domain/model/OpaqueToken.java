package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * The banking token the app presents: {@code k<version>.<43 base64url chars>} (DD 06), i.e. a
 * key version and 32 random bytes. Only its keyed HMAC is ever stored; the value itself is
 * never logged.
 */
public record OpaqueToken(String value) {
    private static final Pattern FORMAT = Pattern.compile("k[1-9][0-9]{0,2}\\.[A-Za-z0-9_-]{43}");

    public OpaqueToken {
        Objects.requireNonNull(value, "value");
        if (!FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("Token has an invalid format");
        }
    }

    /** The {@code k1} part: which lookup HMAC key version the store must use. */
    public String keyVersion() {
        return value.substring(0, value.indexOf('.'));
    }

    @Override
    public String toString() {
        return "OpaqueToken[" + keyVersion() + ".redacted]";
    }
}
