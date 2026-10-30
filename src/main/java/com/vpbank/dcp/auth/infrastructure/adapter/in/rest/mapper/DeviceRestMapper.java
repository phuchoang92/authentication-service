package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import com.vpbank.dcp.auth.application.command.ListDevicesCommand;
import com.vpbank.dcp.auth.application.result.DeviceSummary;
import com.vpbank.dcp.auth.application.result.ListDevicesResult;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.InvalidRequestException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.ErrorCodes;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.DeviceResponse;
import java.util.ArrayList;
import java.util.List;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/** Device list wire ↔ use case. The device ID is shown masked. */
@RequiredArgsConstructor
public final class DeviceRestMapper {
    /** How many trailing characters of the device ID the customer sees. */
    private static final int VISIBLE_SUFFIX_LENGTH = 4;
    private static final String MASK = "…";

    @NonNull private final ErrorMessages errorMessages;

    public ListDevicesCommand toListCommand(String token) {
        try {
            return new ListDevicesCommand(new OpaqueToken(token));
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public ResponseEntity<ApiEnvelope<List<DeviceResponse>>> toResponse(ListDevicesResult result) {
        return switch (result) {
            case ListDevicesResult.Devices devices -> devices(devices);
            case ListDevicesResult.DeviceTrustRequired() ->
                    errorMessages.failure(HttpStatus.FORBIDDEN, ErrorCodes.DEVICE_TRUST_REQUIRED);
            case ListDevicesResult.SessionGone() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.SESSION_REQUIRED);
            case ListDevicesResult.Unavailable() ->
                    errorMessages.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
        };
    }

    private static ResponseEntity<ApiEnvelope<List<DeviceResponse>>> devices(ListDevicesResult.Devices devices) {
        List<DeviceResponse> responses = new ArrayList<>();
        for (DeviceSummary device : devices.devices()) {
            responses.add(toResponse(device));
        }
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
