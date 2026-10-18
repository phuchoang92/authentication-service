package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** The challenge, decrypted with the device key and encrypted again to the server key. */
public record TrustedDeviceVerifyRequest(@NotNull @Size(min = 64, max = 8192) String challengeResponse) {
    @Override
    public String toString() {
        return "TrustedDeviceVerifyRequest[redacted]";
    }
}
