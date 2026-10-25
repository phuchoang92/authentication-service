package com.vpbank.dcp.auth.adapter.in.web.controller;

import com.vpbank.dcp.auth.adapter.in.web.common.ApiEnvelope;
import com.vpbank.dcp.auth.adapter.in.web.dto.request.CaptchaRequest;
import com.vpbank.dcp.auth.adapter.in.web.dto.response.CaptchaResponse;
import com.vpbank.dcp.auth.adapter.in.web.mapper.CaptchaWebMapper;
import com.vpbank.dcp.auth.application.port.in.CaptchaChallenge;
import com.vpbank.dcp.auth.application.port.in.IssueCaptchaUseCase;
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
    @NonNull private final IssueCaptchaUseCase captchas;

    @PostMapping(path = "/api/ns/v1/login/captcha", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<CaptchaResponse>> issue(@Valid @RequestBody CaptchaRequest body) {
        CaptchaChallenge challenge = captchas.issue(CaptchaWebMapper.toUserName(body));
        return CaptchaWebMapper.toResponse(challenge);
    }
}
