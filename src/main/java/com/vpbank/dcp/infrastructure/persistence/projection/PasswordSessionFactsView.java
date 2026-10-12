package com.vpbank.dcp.infrastructure.persistence.projection;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/** Immutable database values; domain restoration belongs to the persistence mapper. */
public record PasswordSessionFactsView(
        UUID operationId,
        UUID journeyId,
        UUID subjectId,
        String appId,
        UUID bindingId,
        byte[] requestKey,
        String requestPublicJwk,
        String responsePublicJwk,
        byte[] deviceKey,
        long customerSecurityVersion,
        long credentialSecurityVersion,
        long deviceSecurityVersion,
        long customerStatusVersion,
        Instant customerCheckedAt,
        String platformAssurance,
        boolean biometricLoginEnabled) {
    public PasswordSessionFactsView {
        Objects.requireNonNull(customerCheckedAt, "customerCheckedAt");
        requestKey = requestKey == null ? null : requestKey.clone();
        deviceKey = deviceKey == null ? null : deviceKey.clone();
    }

    @Override
    public byte[] requestKey() {
        return requestKey == null ? null : requestKey.clone();
    }

    @Override
    public byte[] deviceKey() {
        return deviceKey == null ? null : deviceKey.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PasswordSessionFactsView view
                && Objects.equals(operationId, view.operationId)
                && Objects.equals(journeyId, view.journeyId)
                && Objects.equals(subjectId, view.subjectId)
                && Objects.equals(appId, view.appId)
                && Objects.equals(bindingId, view.bindingId)
                && Arrays.equals(requestKey, view.requestKey)
                && Objects.equals(requestPublicJwk, view.requestPublicJwk)
                && Objects.equals(responsePublicJwk, view.responsePublicJwk)
                && Arrays.equals(deviceKey, view.deviceKey)
                && customerSecurityVersion == view.customerSecurityVersion
                && credentialSecurityVersion == view.credentialSecurityVersion
                && deviceSecurityVersion == view.deviceSecurityVersion
                && customerStatusVersion == view.customerStatusVersion
                && Objects.equals(customerCheckedAt, view.customerCheckedAt)
                && Objects.equals(platformAssurance, view.platformAssurance)
                && biometricLoginEnabled == view.biometricLoginEnabled;
    }

    @Override
    public int hashCode() {
        int hash = Objects.hash(operationId, journeyId, subjectId, appId, bindingId, requestPublicJwk,
                responsePublicJwk, customerSecurityVersion, credentialSecurityVersion, deviceSecurityVersion,
                customerStatusVersion, customerCheckedAt, platformAssurance, biometricLoginEnabled);
        hash = 31 * hash + Arrays.hashCode(requestKey);
        hash = 31 * hash + Arrays.hashCode(deviceKey);
        return hash;
    }

    @Override
    public String toString() {
        return "PasswordSessionFactsView[redacted]";
    }
}
