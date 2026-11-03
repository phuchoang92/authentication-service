package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;

/**
 * SHA-256 of an assertion ID as unpadded base64url (43 characters): the key has a fixed length and shape whatever
 * the caller puts in {@code jti}, and the ID itself is not in the key (RK08).
 */
final class AssertionIdDigest {
    private AssertionIdDigest() {
    }

    static String of(String assertionId) {
        Objects.requireNonNull(assertionId, "assertionId");
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(assertionId.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is not available", failure);
        }
    }
}
