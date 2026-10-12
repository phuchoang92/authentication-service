package com.vpbank.dcp.infrastructure.persistence.projection;

import java.util.Arrays;
import java.util.Objects;

/** Immutable database values; domain restoration belongs to the persistence mapper. */
public record StoredDeviceKeyView(
        byte[] publicKeySpki,
        byte[] thumbprint) {
    public StoredDeviceKeyView {
        Objects.requireNonNull(publicKeySpki, "publicKeySpki");
        Objects.requireNonNull(thumbprint, "thumbprint");
        publicKeySpki = publicKeySpki == null ? null : publicKeySpki.clone();
        thumbprint = thumbprint == null ? null : thumbprint.clone();
    }

    @Override
    public byte[] publicKeySpki() {
        return publicKeySpki == null ? null : publicKeySpki.clone();
    }

    @Override
    public byte[] thumbprint() {
        return thumbprint == null ? null : thumbprint.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof StoredDeviceKeyView view
                && Arrays.equals(publicKeySpki, view.publicKeySpki)
                && Arrays.equals(thumbprint, view.thumbprint);
    }

    @Override
    public int hashCode() {
        int hash = Objects.hash();
        hash = 31 * hash + Arrays.hashCode(publicKeySpki);
        hash = 31 * hash + Arrays.hashCode(thumbprint);
        return hash;
    }

    @Override
    public String toString() {
        return "StoredDeviceKeyView[redacted]";
    }
}
