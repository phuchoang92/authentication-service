package com.vpbank.dcp.auth.adapter.in.web.controller;

import com.vpbank.dcp.auth.adapter.in.web.common.ApiEnvelope;
import com.vpbank.dcp.auth.adapter.in.web.dto.request.RegistrationRequest;
import com.vpbank.dcp.auth.adapter.in.web.dto.response.RegistrationResponse;
import com.vpbank.dcp.auth.adapter.in.web.mapper.RegistrationWebMapper;
import com.vpbank.dcp.auth.application.port.in.RegisterCustomerCommand;
import com.vpbank.dcp.auth.application.port.in.RegisterCustomerResult;
import com.vpbank.dcp.auth.application.port.in.RegisterCustomerUseCase;
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
 * Customer → Auth: create the login account of an onboarded customer (contract §1). Called by
 * the Customer service only; it is off unless {@code auth.registration.enabled=true}, because the
 * caller is not authenticated yet.
 */
@RestController
@ConditionalOnProperty(prefix = "auth.registration", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class RegistrationController {
    @NonNull private final RegisterCustomerUseCase registerCustomer;
    @NonNull private final RegistrationWebMapper mapper;

    @PostMapping(path = "/internal/v1/callback/authentication-creation",
            consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<RegistrationResponse>> create(@Valid @RequestBody RegistrationRequest body) {
        RegisterCustomerCommand command = mapper.toCommand(body);
        RegisterCustomerResult result = registerCustomer.register(command);
        return mapper.toResponse(result);
    }
}
