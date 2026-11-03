package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;

/**
 * Key factory for used BFF assertion IDs (DD 20 §6a): {@code bff-assertion:used:v1:<SHA-256 of the ID, base64url>}.
 * The ID is hashed so the key has a fixed length and shape whatever the BFF puts in {@code jti}. No I/O, no clock.
 */
public final class BffAssertionKeys {
    static final String PREFIX = "bff-assertion:used:v1:";

    public String forAssertionId(String assertionId) {
        Objects.requireNonNull(assertionId, "assertionId");
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(assertionId.getBytes(StandardCharsets.UTF_8));
            return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is not available", failure);
        }
    }
}
