package com.vpbank.dcp.core.device;

import com.vpbank.dcp.core.security.Digest32;
import java.util.Objects;

/** Public Kdev material; owner/status are rechecked after signed KC identity resolution. */
public final class StoredDeviceKey {

    private final byte[] publicKeySpki;
    private final Digest32 thumbprint;

    public StoredDeviceKey(byte[] publicKeySpki, Digest32 thumbprint) {
        this.publicKeySpki = Objects.requireNonNull(publicKeySpki, "publicKeySpki").clone();
        this.thumbprint = Objects.requireNonNull(thumbprint, "thumbprint");
        if (publicKeySpki.length == 0 || publicKeySpki.length > 4096) {
            throw new IllegalArgumentException("Device public key must be 1 to 4096 bytes");
        }
    }

    public byte[] publicKeySpki() { return publicKeySpki.clone(); }
    public Digest32 thumbprint() { return thumbprint; }

    @Override
    public String toString() { return "StoredDeviceKey[redacted]"; }
}
