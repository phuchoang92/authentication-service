package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import com.vpbank.dcp.auth.application.port.in.IssueCaptchaUseCase;
import com.vpbank.dcp.auth.application.result.CaptchaChallenge;
import com.vpbank.dcp.auth.domain.model.UserName;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.CaptchaRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.CaptchaResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.CaptchaRestMapper;
import jakarta.validation.Valid;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** App → Auth (no session): a CAPTCHA for the next login attempt. */
@RestController
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class CaptchaController {
    @NonNull private final IssueCaptchaUseCase issueCaptchaUseCase;

    @PostMapping(path = "/api/ns/v1/login/captcha", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<CaptchaResponse>> issue(@Valid @RequestBody CaptchaRequest body) {
        UserName userName = CaptchaRestMapper.toUserName(body);
        CaptchaChallenge challenge = issueCaptchaUseCase.issue(userName);
        return CaptchaRestMapper.toResponse(challenge);
    }
}
