package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto;

import java.util.Objects;
import tools.jackson.databind.JsonNode;

public record TrustedDeviceInitResponse(String status, JsonNode serverPublicJwk, String challenge)
        implements TrustedDeviceResponse {
    public TrustedDeviceInitResponse {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(serverPublicJwk, "serverPublicJwk");
        Objects.requireNonNull(challenge, "challenge");
    }

    @Override
    public String toString() {
        return "TrustedDeviceInitResponse[redacted]";
    }
}
