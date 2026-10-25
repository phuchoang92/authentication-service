package com.vpbank.dcp.auth.adapter.in.web.controller;

import com.vpbank.dcp.auth.adapter.in.web.common.ApiEnvelope;
import com.vpbank.dcp.auth.adapter.in.web.common.SessionFilter;
import com.vpbank.dcp.auth.adapter.in.web.mapper.SessionWebMapper;
import com.vpbank.dcp.auth.application.port.in.LogoutCommand;
import com.vpbank.dcp.auth.application.port.in.LogoutResult;
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
    @NonNull private final SessionWebMapper mapper;

    @PostMapping(path = "/api/v1/logout")
    public ResponseEntity<ApiEnvelope<Void>> logout(@RequestAttribute(SessionFilter.TOKEN_ATTRIBUTE) String token) {
        LogoutCommand command = mapper.toLogoutCommand(token);
        LogoutResult result = logout.logout(command);
        return mapper.toResponse(result);
    }
}
