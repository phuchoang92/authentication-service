package com.vpbank.dcp.auth.adapter.in.web.controller;

import com.vpbank.dcp.auth.adapter.in.web.common.ApiEnvelope;
import com.vpbank.dcp.auth.adapter.in.web.dto.request.LoginRequest;
import com.vpbank.dcp.auth.adapter.in.web.dto.response.LoginResponse;
import com.vpbank.dcp.auth.adapter.in.web.mapper.LoginWebMapper;
import com.vpbank.dcp.auth.application.port.in.LoginCommand;
import com.vpbank.dcp.auth.application.port.in.LoginResult;
import com.vpbank.dcp.auth.application.port.in.LoginUseCase;
import jakarta.validation.Valid;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** App → Auth (via BFF), no session yet: {@code /api/ns}. Off unless {@code auth.login.enabled=true}. */
@RestController
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class LoginController {
    @NonNull private final LoginUseCase login;
    @NonNull private final LoginWebMapper mapper;

    @PostMapping(path = "/api/ns/v1/login", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<LoginResponse>> login(@Valid @RequestBody LoginRequest body) {
        LoginCommand command = mapper.toCommand(body);
        LoginResult result = login.login(command);
        return mapper.toResponse(result);
    }
}
