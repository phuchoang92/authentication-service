package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import com.vpbank.dcp.auth.application.port.in.ListDevicesUseCase;
import com.vpbank.dcp.auth.application.result.DeviceSummary;
import com.vpbank.dcp.auth.application.result.SessionSummary;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.SessionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.DeviceResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.DeviceRestMapper;
import java.util.List;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RestController;

/** App → Auth (ACTIVE session): the caller's devices on its channel; the filter already resolved the session. */
@RestController
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class DeviceController {
    @NonNull private final ListDevicesUseCase listDevicesUseCase;

    @GetMapping(path = "/api/v1/devices", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<List<DeviceResponse>>> list(
            @RequestAttribute(SessionFilter.SESSION_ATTRIBUTE) SessionSummary session) {
        List<DeviceSummary> deviceSummaries = listDevicesUseCase.list(session.customerId(), session.channel());
        return DeviceRestMapper.toResponse(deviceSummaries);
    }
}
