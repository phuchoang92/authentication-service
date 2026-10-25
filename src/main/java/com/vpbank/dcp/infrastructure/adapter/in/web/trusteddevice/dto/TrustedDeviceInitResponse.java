package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto;

import java.util.Objects;
import java.util.UUID;

/** {@code publicKey} is Ksrv's public key; the App seals its proof to it. */
public record TrustedDeviceInitResponse(String status, UUID enrollmentId, String suite,
                                        String publicKey, String protectedChallenge)
        implements TrustedDeviceResponse {
    public TrustedDeviceInitResponse {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(enrollmentId, "enrollmentId");
        Objects.requireNonNull(suite, "suite");
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(protectedChallenge, "protectedChallenge");
    }

    @Override
    public String toString() {
        return "TrustedDeviceInitResponse[redacted]";
    }
}
