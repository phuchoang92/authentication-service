package com.vpbank.dcp.infrastructure.persistence.projection;

import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/** Immutable database values; domain restoration belongs to the persistence mapper. */
public record PasswordReservationView(
        UUID operationId,
        UUID journeyId,
        byte[] commandDigest,
        String commandKeyId) {
    public PasswordReservationView {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(journeyId, "journeyId");
        Objects.requireNonNull(commandDigest, "commandDigest");
        Objects.requireNonNull(commandKeyId, "commandKeyId");
        commandDigest = commandDigest == null ? null : commandDigest.clone();
    }

    @Override
    public byte[] commandDigest() {
        return commandDigest == null ? null : commandDigest.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PasswordReservationView view
                && Objects.equals(operationId, view.operationId)
                && Objects.equals(journeyId, view.journeyId)
                && Arrays.equals(commandDigest, view.commandDigest)
                && Objects.equals(commandKeyId, view.commandKeyId);
    }

    @Override
    public int hashCode() {
        int hash = Objects.hash(operationId, journeyId, commandKeyId);
        hash = 31 * hash + Arrays.hashCode(commandDigest);
        return hash;
    }

    @Override
    public String toString() {
        return "PasswordReservationView[redacted]";
    }
}
