package com.vpbank.dcp.auth.core.customer;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Keyed digest of the registration request. Two calls with the same digest carry the same data,
 * so the second one is a retry, not a conflict.
 */
public final class RequestDigest {
    private final byte[] bytes;

    public RequestDigest(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        if (bytes.length != 32) {
            throw new IllegalArgumentException("Request digest must be 32 bytes");
        }
        this.bytes = bytes.clone();
    }

    public byte[] bytes() {
        return bytes.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof RequestDigest digest && Arrays.equals(bytes, digest.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return "RequestDigest[" + HexFormat.of().formatHex(bytes, 0, 4) + "…]";
    }
}
