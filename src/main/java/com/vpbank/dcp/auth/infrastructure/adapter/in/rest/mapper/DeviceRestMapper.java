package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import com.vpbank.dcp.auth.application.result.DeviceSummary;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.DeviceResponse;
import java.util.List;
import org.springframework.http.ResponseEntity;

/** Device list → wire. Static: no localized text. The device ID is shown masked. */
public final class DeviceRestMapper {
    /** How many trailing characters of the device ID the customer sees. */
    private static final int VISIBLE_SUFFIX_LENGTH = 4;
    private static final String MASK = "…";

    private DeviceRestMapper() {
    }

    public static ResponseEntity<ApiEnvelope<List<DeviceResponse>>> toResponse(List<DeviceSummary> deviceSummaries) {
        List<DeviceResponse> responses = deviceSummaries.stream()
                .map(DeviceRestMapper::toResponse)
                .toList();
        return ResponseEntity.ok(ApiEnvelope.success(responses));
    }

    static DeviceResponse toResponse(DeviceSummary device) {
        return new DeviceResponse(
                mask(device.deviceId().value()),
                device.platform().name(),
                device.status().name(),
                device.trustLevel().name(),
                device.primary(),
                device.trustedAt(),
                device.expiresAt(),
                device.lastLoginAt());
    }

    static String mask(String deviceId) {
        int visibleLength = Math.min(VISIBLE_SUFFIX_LENGTH, deviceId.length());
        String visibleSuffix = deviceId.substring(deviceId.length() - visibleLength);
        return MASK + visibleSuffix;
    }
}
