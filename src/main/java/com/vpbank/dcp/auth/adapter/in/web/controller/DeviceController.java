package com.vpbank.dcp.auth.adapter.in.web.controller;

import com.vpbank.dcp.auth.adapter.in.web.common.ApiEnvelope;
import com.vpbank.dcp.auth.adapter.in.web.common.SessionFilter;
import com.vpbank.dcp.auth.adapter.in.web.dto.response.DeviceResponse;
import com.vpbank.dcp.auth.adapter.in.web.mapper.DeviceWebMapper;
import com.vpbank.dcp.auth.application.port.in.DeviceSummary;
import com.vpbank.dcp.auth.application.port.in.ListDevicesUseCase;
import com.vpbank.dcp.auth.application.port.in.SessionSummary;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** App → Auth (ACTIVE session): the caller's devices on its channel; the filter already resolved the session. */
@RestController
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class DeviceController {
    @NonNull private final ListDevicesUseCase devices;

    @GetMapping(path = "/api/v1/devices", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<List<DeviceResponse>>> list(
            @RequestAttribute(SessionFilter.SESSION_ATTRIBUTE) SessionSummary session) {
        List<DeviceSummary> list = devices.list(session.customerId(), session.channel());
        return DeviceWebMapper.toResponse(list);
    }
}
