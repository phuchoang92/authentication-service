package com.vpbank.dcp.auth.adapter.in.web.mapper;

import com.vpbank.dcp.auth.adapter.in.web.common.ApiEnvelope;
import com.vpbank.dcp.auth.adapter.in.web.dto.response.DeviceResponse;
import com.vpbank.dcp.auth.application.port.in.DeviceSummary;
import org.springframework.http.ResponseEntity;

import java.util.List;

/** Device list → wire. Static: no localized text. The device ID is shown masked. */
public final class DeviceWebMapper {
    private static final int VISIBLE = 4;

    private DeviceWebMapper() {
    }

    public static ResponseEntity<ApiEnvelope<List<DeviceResponse>>> toResponse(List<DeviceSummary> devices) {
        return ResponseEntity.ok(ApiEnvelope.success(devices.stream().map(DeviceWebMapper::toResponse).toList()));
    }

    static DeviceResponse toResponse(DeviceSummary device) {
        return new DeviceResponse(mask(device.deviceId().value()), device.platform().name(), device.status().name(),
                device.trustLevel().name(), device.primary(), device.trustedAt(), device.expiresAt(), device.lastLoginAt());
    }

    static String mask(String deviceId) {
        int keep = Math.min(VISIBLE, deviceId.length());
        return "…" + deviceId.substring(deviceId.length() - keep);
    }
}
