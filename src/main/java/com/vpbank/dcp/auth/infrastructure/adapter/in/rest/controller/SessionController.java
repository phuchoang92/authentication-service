package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.SessionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.SessionRestMapper;
import com.vpbank.dcp.auth.application.command.LogoutCommand;
import com.vpbank.dcp.auth.application.result.LogoutResult;
import com.vpbank.dcp.auth.application.port.in.LogoutUseCase;
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
    @NonNull private final LogoutUseCase logout;
    @NonNull private final SessionRestMapper mapper;

    @PostMapping(path = "/api/v1/logout")
    public ResponseEntity<ApiEnvelope<Void>> logout(@RequestAttribute(SessionFilter.TOKEN_ATTRIBUTE) String token) {
        LogoutCommand command = mapper.toLogoutCommand(token);
        LogoutResult result = logout.logout(command);
        return mapper.toResponse(result);
    }
}
