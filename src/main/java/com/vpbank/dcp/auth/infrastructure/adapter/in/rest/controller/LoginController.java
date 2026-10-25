package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import com.vpbank.dcp.auth.application.command.LoginCommand;
import com.vpbank.dcp.auth.application.port.in.LoginUseCase;
import com.vpbank.dcp.auth.application.result.LoginResult;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.LoginRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.LoginResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.LoginRestMapper;
import jakarta.validation.Valid;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * App → Auth (via BFF), no session yet: {@code /api/ns}. Off unless {@code auth.login.enabled=true}.
 */
@RestController
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class LoginController {
    @NonNull
    private final LoginUseCase loginUseCase;
    @NonNull
    private final LoginRestMapper loginRestMapper;

    @PostMapping(path = "/api/ns/v1/login", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<LoginResponse>> login(@Valid @RequestBody LoginRequest body) {
        LoginCommand command = loginRestMapper.toCommand(body);
        LoginResult result = loginUseCase.login(command);
        return loginRestMapper.toResponse(result);
    }
}
