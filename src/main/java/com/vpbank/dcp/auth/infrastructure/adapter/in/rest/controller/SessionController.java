package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import com.vpbank.dcp.auth.application.command.LogoutCommand;
import com.vpbank.dcp.auth.application.port.in.LogoutUseCase;
import com.vpbank.dcp.auth.application.result.LogoutResult;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.SessionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.SessionRestMapper;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RestController;

/** App → Auth, session-checked ({@code /api}): the filter already resolved the token. */
@RestController
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class SessionController {
    @NonNull private final LogoutUseCase logoutUseCase;
    @NonNull private final SessionRestMapper sessionRestMapper;

    @PostMapping(path = "/api/v1/logout")
    public ResponseEntity<ApiEnvelope<Void>> logout(@RequestAttribute(SessionFilter.TOKEN_ATTRIBUTE) String token) {
        LogoutCommand command = sessionRestMapper.toLogoutCommand(token);
        LogoutResult result = logoutUseCase.logout(command);
        return sessionRestMapper.toResponse(result);
    }
}
