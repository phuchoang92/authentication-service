package com.vpbank.dcp.auth.domain.model;

import lombok.Builder;
import lombok.NonNull;

/**
 * What init knows when it challenges a new device (DD 20 §4): the enrollment, the restricted session of the
 * new device, the device key to trust, this transaction's server key pair (Ksrv) and the digest of the
 * challenge sent. {@code targetDeviceId} is the device row a known device already has; it is null for a
 * device Auth has never seen, whose row is made by the trust commit.
 */
@Builder
public record KeyExchangeStart(@NonNull EnrollmentId enrollmentId,
                               @NonNull AdmittedSession newDeviceSession,
                               TrustedDeviceId targetDeviceId,
                               @NonNull DeviceKey deviceKey,
                               @NonNull String serverPublicJwk,
                               @NonNull String serverPrivateJwk,
                               @NonNull String challengeDigest) {
    @Override
    public String toString() {
        return "KeyExchangeStart[enrollmentId=" + enrollmentId + ", redacted]";
    }
}
