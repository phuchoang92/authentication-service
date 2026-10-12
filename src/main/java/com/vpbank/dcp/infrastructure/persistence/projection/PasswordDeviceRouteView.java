package com.vpbank.dcp.infrastructure.persistence.projection;

import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/** Immutable database values; domain restoration belongs to the persistence mapper. */
public record PasswordDeviceRouteView(
        UUID claimedBindingId,
        UUID lastSuccessfulBindingId,
        byte[] installationHash,
        byte[] deviceProofThumbprint,
        DeviceCandidateView candidate) {
    public PasswordDeviceRouteView {
        Objects.requireNonNull(installationHash, "installationHash");
        installationHash = installationHash == null ? null : installationHash.clone();
        deviceProofThumbprint = deviceProofThumbprint == null ? null : deviceProofThumbprint.clone();
    }

    @Override
    public byte[] installationHash() {
        return installationHash == null ? null : installationHash.clone();
    }

    @Override
    public byte[] deviceProofThumbprint() {
        return deviceProofThumbprint == null ? null : deviceProofThumbprint.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PasswordDeviceRouteView view
                && Objects.equals(claimedBindingId, view.claimedBindingId)
                && Objects.equals(lastSuccessfulBindingId, view.lastSuccessfulBindingId)
                && Arrays.equals(installationHash, view.installationHash)
                && Arrays.equals(deviceProofThumbprint, view.deviceProofThumbprint)
                && Objects.equals(candidate, view.candidate);
    }

    @Override
    public int hashCode() {
        int hash = Objects.hash(claimedBindingId, lastSuccessfulBindingId, candidate);
        hash = 31 * hash + Arrays.hashCode(installationHash);
        hash = 31 * hash + Arrays.hashCode(deviceProofThumbprint);
        return hash;
    }

    @Override
    public String toString() {
        return "PasswordDeviceRouteView[redacted]";
    }
}
