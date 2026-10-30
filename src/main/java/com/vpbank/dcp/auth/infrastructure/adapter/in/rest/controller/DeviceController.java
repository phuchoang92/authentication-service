package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import com.vpbank.dcp.auth.application.command.ListDevicesCommand;
import com.vpbank.dcp.auth.application.port.in.ListDevicesUseCase;
import com.vpbank.dcp.auth.application.result.ListDevicesResult;
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

/** App → Auth (ACTIVE session): the caller's devices on its channel; the use case resolves the session once. */
@RestController
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class DeviceController {
    @NonNull
    private final ListDevicesUseCase listDevicesUseCase;
    @NonNull
    private final DeviceRestMapper deviceRestMapper;

    @GetMapping(path = "/api/v1/devices", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<List<DeviceResponse>>> list(
            @RequestAttribute(SessionFilter.TOKEN_ATTRIBUTE) String token) {
        ListDevicesCommand command = deviceRestMapper.toListCommand(token);
        ListDevicesResult result = listDevicesUseCase.list(command);
        return deviceRestMapper.toResponse(result);
    }
}
