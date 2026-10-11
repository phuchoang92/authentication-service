package com.vpbank.dcp.core.domain.security;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

public final class Digest32 {

    private final byte[] bytes;

    private Digest32(byte[] bytes) {
        this.bytes = bytes.clone();
    }

    public static Digest32 fromBytes(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        if (bytes.length != 32) {
            throw new InvalidDigestException();
        }
        return new Digest32(bytes);
    }

    public static Digest32 fromBase64Url(String encoded) {
        Objects.requireNonNull(encoded, "encoded");
        if (!encoded.matches("[A-Za-z0-9_-]{43}")) {
            throw new InvalidDigestException();
        }
        try {
            Digest32 digest = fromBytes(Base64.getUrlDecoder().decode(encoded));
            if (!digest.base64Url().equals(encoded)) {
                throw new InvalidDigestException();
            }
            return digest;
        } catch (IllegalArgumentException invalid) {
            throw new InvalidDigestException(invalid);
        }
    }

    public byte[] bytes() {
        return bytes.clone();
    }

    public String base64Url() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof Digest32 digest && Arrays.equals(bytes, digest.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return "Digest32[redacted]";
    }
}
