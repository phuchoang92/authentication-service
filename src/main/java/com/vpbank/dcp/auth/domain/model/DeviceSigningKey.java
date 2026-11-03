package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * The public signing key an app installation proved it holds (slice 13): the canonical JWK text the
 * verifier produced, and the RFC 7638 thumbprint that names it ({@code kid}). Two keys are the same key
 * when their canonical texts are equal; the thumbprint is what a session or an audit row records.
 */
public record DeviceSigningKey(String publicJwk, String thumbprint) {
    private static final Pattern THUMBPRINT = Pattern.compile("[A-Za-z0-9_-]{43}");

    public DeviceSigningKey {
        Objects.requireNonNull(publicJwk, "publicJwk");
        Objects.requireNonNull(thumbprint, "thumbprint");
        if (publicJwk.isBlank()) {
            throw new IllegalArgumentException("A device signing key needs its public JWK");
        }
        if (!THUMBPRINT.matcher(thumbprint).matches()) {
            throw new IllegalArgumentException("A key thumbprint is 43 base64url characters");
        }
    }

    @Override
    public String toString() {
        return "DeviceSigningKey[thumbprint=" + thumbprint + "]";
    }
}
