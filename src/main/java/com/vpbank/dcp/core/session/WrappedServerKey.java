package com.vpbank.dcp.core.session;

import java.util.Arrays;
import java.util.Objects;

/** Ksrv's private key, encrypted under a versioned wrapping key. Never the plaintext key. */
public record WrappedServerKey(String keyId, byte[] ciphertext) {
    public WrappedServerKey {
        Objects.requireNonNull(ciphertext, "ciphertext");
        if (keyId == null || !keyId.matches("[A-Za-z0-9_-]{1,16}") || ciphertext.length == 0) {
            throw new IllegalArgumentException("Invalid restricted session value");
        }
        ciphertext = ciphertext.clone();
    }

    @Override
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof WrappedServerKey that && keyId.equals(that.keyId)
                && Arrays.equals(ciphertext, that.ciphertext);
    }

    @Override
    public int hashCode() {
        return 31 * keyId.hashCode() + Arrays.hashCode(ciphertext);
    }

    @Override
    public String toString() {
        return "WrappedServerKey[redacted]";
    }
}
