package com.vpbank.dcp.infrastructure.persistence.projection;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/** Immutable database values; domain restoration belongs to the persistence mapper. */
public record DeviceCandidateView(
        UUID bindingId,
        UUID subjectId,
        String appId,
        byte[] installationHash,
        String bindingState,
        Instant expiresAt,
        String keyState,
        Integer keyVersion,
        byte[] keyThumbprint) {
    public DeviceCandidateView {
        Objects.requireNonNull(bindingId, "bindingId");
        Objects.requireNonNull(subjectId, "subjectId");
        Objects.requireNonNull(appId, "appId");
        Objects.requireNonNull(installationHash, "installationHash");
        Objects.requireNonNull(expiresAt, "expiresAt");
        installationHash = installationHash == null ? null : installationHash.clone();
        keyThumbprint = keyThumbprint == null ? null : keyThumbprint.clone();
    }

    @Override
    public byte[] installationHash() {
        return installationHash == null ? null : installationHash.clone();
    }

    @Override
    public byte[] keyThumbprint() {
        return keyThumbprint == null ? null : keyThumbprint.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof DeviceCandidateView view
                && Objects.equals(bindingId, view.bindingId)
                && Objects.equals(subjectId, view.subjectId)
                && Objects.equals(appId, view.appId)
                && Arrays.equals(installationHash, view.installationHash)
                && Objects.equals(bindingState, view.bindingState)
                && Objects.equals(expiresAt, view.expiresAt)
                && Objects.equals(keyState, view.keyState)
                && Objects.equals(keyVersion, view.keyVersion)
                && Arrays.equals(keyThumbprint, view.keyThumbprint);
    }

    @Override
    public int hashCode() {
        int hash = Objects.hash(bindingId, subjectId, appId, bindingState, expiresAt, keyState, keyVersion);
        hash = 31 * hash + Arrays.hashCode(installationHash);
        hash = 31 * hash + Arrays.hashCode(keyThumbprint);
        return hash;
    }

    @Override
    public String toString() {
        return "DeviceCandidateView[redacted]";
    }
}
