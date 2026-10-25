package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request;

import jakarta.validation.constraints.Pattern;
import java.util.Map;

/**
 * {@code POST /api/v1/trusted-device/init}. A new device sends its public P-256 JWK and platform;
 * a known device may send {@code {}} and keep the key and platform Auth already stores (DD 20 §4).
 */
public record InitEnrollmentRequest(
        Map<String, Object> devicePublicJwk,
        @Pattern(regexp = "ANDROID|IOS", message = "{auth.format}") String platform) {
    @Override
    public String toString() {
        return "InitEnrollmentRequest[platform=" + platform + ", redacted]";
    }
}
