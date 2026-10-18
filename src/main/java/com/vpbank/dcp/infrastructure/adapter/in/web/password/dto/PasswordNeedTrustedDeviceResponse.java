package com.vpbank.dcp.infrastructure.adapter.in.web.password.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/**
 * The password is correct, but this device must be trusted first. The restricted token is
 * encrypted to Kenc like an ACTIVE one, and its receipt says NEED_TRUSTED_DEVICE. It is usable
 * only by the trusted-device API.
 */
public record PasswordNeedTrustedDeviceResponse(String status, String tokenEnvelope, String receipt,
                                                @JsonProperty("expires_in") long expiresIn)
        implements PasswordLoginResponse {
    public PasswordNeedTrustedDeviceResponse {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(tokenEnvelope, "tokenEnvelope");
        Objects.requireNonNull(receipt, "receipt");
    }

    @Override
    public String toString() {
        return "PasswordNeedTrustedDeviceResponse[redacted]";
    }
}
