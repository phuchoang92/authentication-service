package com.vpbank.dcp.auth.application.port.out;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * How a session is addressed without its token: the token's key version and the unpadded
 * base64url HMAC digest (43 characters). The BFF computes the same pair to read Valkey.
 */
public record SessionLookup(String keyVersion, String digest) {
    private static final Pattern KEY_VERSION = Pattern.compile("k[1-9][0-9]{0,2}");
    private static final Pattern DIGEST = Pattern.compile("[A-Za-z0-9_-]{43}");

    public SessionLookup {
        Objects.requireNonNull(keyVersion, "keyVersion");
        Objects.requireNonNull(digest, "digest");
        if (!KEY_VERSION.matcher(keyVersion).matches() || !DIGEST.matcher(digest).matches()) {
            throw new IllegalArgumentException("Session lookup has an invalid shape");
        }
    }

    @Override
    public String toString() {
        return keyVersion + ":" + digest.substring(0, 6) + "…";
    }
}
