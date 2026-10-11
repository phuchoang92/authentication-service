package com.vpbank.dcp.infrastructure.adapter.out.http;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/** RFC 3986 path-segment encoding; unlike form encoding, spaces never become '+'. */
public final class ExternalPath {

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private ExternalPath() {
    }

    public static String segment(String value) {
        Objects.requireNonNull(value, "value");
        if (value.isEmpty()) {
            throw new InvalidExternalHttpSettingsException();
        }
        StringBuilder result = new StringBuilder();
        for (byte octet : value.getBytes(StandardCharsets.UTF_8)) {
            int unsigned = octet & 0xff;
            if (unreserved(unsigned)) {
                result.append((char) unsigned);
            } else {
                result.append('%').append(HEX[unsigned >>> 4]).append(HEX[unsigned & 15]);
            }
        }
        return result.toString();
    }

    private static boolean unreserved(int value) {
        return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
                || value >= '0' && value <= '9' || value == '-' || value == '_'
                || value == '.' || value == '~';
    }
}
