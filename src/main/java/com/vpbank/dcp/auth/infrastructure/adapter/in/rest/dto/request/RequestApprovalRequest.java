package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request;

import jakarta.validation.constraints.Pattern;
import java.util.Map;

/**
 * {@code POST /api/v1/trusted-device/request}. A new installation sends its public P-256 JWK and platform;
 * an installation Auth already knows may send {@code {}} and keeps its stored key and platform.
 */
public record RequestApprovalRequest(

        Map<String, Object> devicePublicJwk,

        @Pattern(regexp = "ANDROID|IOS", message = "{auth.format}")
        String platform) {

    @Override
    public String toString() {
        return "RequestApprovalRequest[platform=" + platform + ", redacted]";
    }
}
