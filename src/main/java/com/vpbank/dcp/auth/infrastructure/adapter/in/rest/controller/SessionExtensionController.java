package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.ExtendSessionRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.ExtendSessionResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.SessionRestMapper;
import com.vpbank.dcp.auth.application.command.ExtendSessionCommand;
import com.vpbank.dcp.auth.application.result.ExtendSessionResult;
import com.vpbank.dcp.auth.application.port.in.ExtendSessionUseCase;
import jakarta.validation.Valid;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** BFF → Auth ({@code /internal}) after it admitted a request: slide the idle deadline (flow 16). */
@RestController
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class SessionExtensionController {
    @NonNull private final ExtendSessionUseCase extend;
    @NonNull private final SessionRestMapper mapper;

    @PostMapping(path = "/internal/v1/sessions/extend", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<ExtendSessionResponse>> extend(@Valid @RequestBody ExtendSessionRequest body) {
        ExtendSessionCommand command = mapper.toCommand(body);
        ExtendSessionResult result = extend.extend(command);
        return mapper.toResponse(result);
    }
}
