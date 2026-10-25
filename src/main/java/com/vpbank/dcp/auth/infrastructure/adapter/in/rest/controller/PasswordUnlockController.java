package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.PasswordUnlockRestMapper;
import com.vpbank.dcp.auth.application.result.UnlockPasswordResult;
import com.vpbank.dcp.auth.application.port.in.UnlockPasswordUseCase;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/** Bank tooling → Auth ({@code /internal}): clear a password lockout. No caller authentication yet. */
@RestController
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class PasswordUnlockController {
    @NonNull private final UnlockPasswordUseCase unlock;
    @NonNull private final PasswordUnlockRestMapper mapper;

    @PostMapping(path = "/internal/v1/customers/{customerId}/password-unlock")
    public ResponseEntity<ApiEnvelope<Void>> unlock(@PathVariable String customerId) {
        UnlockPasswordResult result = unlock.unlock(mapper.toCustomerId(customerId));
        return mapper.toResponse(result);
    }
}
