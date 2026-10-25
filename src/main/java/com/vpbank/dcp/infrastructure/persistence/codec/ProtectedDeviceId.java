package com.vpbank.dcp.infrastructure.persistence.codec;

import com.vpbank.dcp.core.security.Digest32;
import java.util.Objects;

/** Storage representation, not a device-possession proof. */
public final class ProtectedDeviceId {
    private final Digest32 lookup;
    private final String lookupKeyId;
    private final byte[] ciphertext;
    private final String encryptionKeyId;

    public ProtectedDeviceId(Digest32 lookup, String lookupKeyId,
                             byte[] ciphertext, String encryptionKeyId) {
        this.lookup = Objects.requireNonNull(lookup);
        this.lookupKeyId = Objects.requireNonNull(lookupKeyId);
        this.ciphertext = Objects.requireNonNull(ciphertext).clone();
        this.encryptionKeyId = Objects.requireNonNull(encryptionKeyId);
    }

    public Digest32 lookup() {
        return lookup;
    }

    public String lookupKeyId() {
        return lookupKeyId;
    }

    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    public String encryptionKeyId() {
        return encryptionKeyId;
    }

    @Override
    public String toString() {
        return "ProtectedDeviceId[redacted]";
    }
}
