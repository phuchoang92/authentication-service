package com.vpbank.dcp.infrastructure.adapter.out.totp;

import java.util.Objects;

/** Database representation; ciphertext is copied and never rendered in diagnostics. */
public final class ProtectedTotpSecret {
    private final String keyId;
    private final byte[] ciphertext;

    public ProtectedTotpSecret(String keyId, byte[] ciphertext) {
        this.keyId = Objects.requireNonNull(keyId, "keyId");
        this.ciphertext = Objects.requireNonNull(ciphertext, "ciphertext").clone();
    }

    public String keyId() {
        return keyId;
    }

    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    @Override
    public String toString() {
        return "ProtectedTotpSecret[redacted]";
    }
}
