package com.vpbank.dcp.infrastructure.persistence.projection;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/** Immutable database values; domain restoration belongs to the persistence mapper. */
public record PreparedPasswordSessionView(
        UUID intentId,
        UUID sessionId,
        UUID generation,
        String lookupVersion,
        byte[] lookupDigest,
        byte[] candidateDigest,
        Instant idleExpiresAt,
        Instant absoluteExpiresAt,
        Instant deliveryDeadline,
        byte[] protectedResult,
        byte[] resultDigest,
        long customerSecurityVersion,
        long credentialSecurityVersion,
        long deviceSecurityVersion,
        byte[] requestKey,
        UUID bindingId,
        UUID subjectId) {
    public PreparedPasswordSessionView {
        Objects.requireNonNull(resultDigest, "resultDigest");
        lookupDigest = lookupDigest == null ? null : lookupDigest.clone();
        candidateDigest = candidateDigest == null ? null : candidateDigest.clone();
        protectedResult = protectedResult == null ? null : protectedResult.clone();
        resultDigest = resultDigest == null ? null : resultDigest.clone();
        requestKey = requestKey == null ? null : requestKey.clone();
    }

    @Override
    public byte[] lookupDigest() {
        return lookupDigest == null ? null : lookupDigest.clone();
    }

    @Override
    public byte[] candidateDigest() {
        return candidateDigest == null ? null : candidateDigest.clone();
    }

    @Override
    public byte[] protectedResult() {
        return protectedResult == null ? null : protectedResult.clone();
    }

    @Override
    public byte[] resultDigest() {
        return resultDigest == null ? null : resultDigest.clone();
    }

    @Override
    public byte[] requestKey() {
        return requestKey == null ? null : requestKey.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PreparedPasswordSessionView view
                && Objects.equals(intentId, view.intentId)
                && Objects.equals(sessionId, view.sessionId)
                && Objects.equals(generation, view.generation)
                && Objects.equals(lookupVersion, view.lookupVersion)
                && Arrays.equals(lookupDigest, view.lookupDigest)
                && Arrays.equals(candidateDigest, view.candidateDigest)
                && Objects.equals(idleExpiresAt, view.idleExpiresAt)
                && Objects.equals(absoluteExpiresAt, view.absoluteExpiresAt)
                && Objects.equals(deliveryDeadline, view.deliveryDeadline)
                && Arrays.equals(protectedResult, view.protectedResult)
                && Arrays.equals(resultDigest, view.resultDigest)
                && customerSecurityVersion == view.customerSecurityVersion
                && credentialSecurityVersion == view.credentialSecurityVersion
                && deviceSecurityVersion == view.deviceSecurityVersion
                && Arrays.equals(requestKey, view.requestKey)
                && Objects.equals(bindingId, view.bindingId)
                && Objects.equals(subjectId, view.subjectId);
    }

    @Override
    public int hashCode() {
        int hash = Objects.hash(intentId, sessionId, generation, lookupVersion, idleExpiresAt,
                absoluteExpiresAt, deliveryDeadline, customerSecurityVersion, credentialSecurityVersion,
                deviceSecurityVersion, bindingId, subjectId);
        hash = 31 * hash + Arrays.hashCode(lookupDigest);
        hash = 31 * hash + Arrays.hashCode(candidateDigest);
        hash = 31 * hash + Arrays.hashCode(protectedResult);
        hash = 31 * hash + Arrays.hashCode(resultDigest);
        hash = 31 * hash + Arrays.hashCode(requestKey);
        return hash;
    }

    @Override
    public String toString() {
        return "PreparedPasswordSessionView[redacted]";
    }
}
