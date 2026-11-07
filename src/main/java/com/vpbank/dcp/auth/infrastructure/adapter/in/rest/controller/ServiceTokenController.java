package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import com.vpbank.dcp.auth.application.command.IssueServiceTokenCommand;
import com.vpbank.dcp.auth.application.port.in.IssueServiceTokenUseCase;
import com.vpbank.dcp.auth.application.result.IssueServiceTokenResult;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ServiceClientAssertionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.VerifiedServiceClient;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.IssueServiceTokenRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.ServiceTokenResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.ServiceTokenRestMapper;
import jakarta.validation.Valid;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Internal service → Auth ({@code /internal}, slice 12): a scoped token for a flow without a customer session.
 * The caller is whoever {@link ServiceClientAssertionFilter} verified.
 */
@RestController
@ConditionalOnProperty(prefix = "auth.service-token", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class ServiceTokenController {
    @NonNull
    private final IssueServiceTokenUseCase issueServiceTokenUseCase;
    @NonNull
    private final ServiceTokenRestMapper serviceTokenRestMapper;

    @PostMapping(path = ServiceClientAssertionFilter.ISSUE_PATH, consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<ServiceTokenResponse>> issue(
            @RequestAttribute(ServiceClientAssertionFilter.CALLING_SERVICE_ATTRIBUTE)
            VerifiedServiceClient callingService,
            @Valid @RequestBody IssueServiceTokenRequest body) {
        IssueServiceTokenCommand command = serviceTokenRestMapper.toCommand(callingService, body);
        IssueServiceTokenResult result = issueServiceTokenUseCase.issue(command);
        return serviceTokenRestMapper.toResponse(result);
    }
}
