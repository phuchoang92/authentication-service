package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.UUID;

/** The challenge, opened with the device key and sealed again to the server key. */
public record TrustedDeviceVerifyRequest(@NotNull UUID enrollmentId,
                                         @NotNull @Size(min = 64, max = 8192) String keyExchangeProof) {
    @Override
    public String toString() {
        return "TrustedDeviceVerifyRequest[redacted]";
    }
}
