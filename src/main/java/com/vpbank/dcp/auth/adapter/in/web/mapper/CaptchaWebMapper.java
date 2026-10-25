package com.vpbank.dcp.auth.adapter.in.web.mapper;

import com.vpbank.dcp.auth.adapter.in.web.common.ApiEnvelope;
import com.vpbank.dcp.auth.adapter.in.web.common.InvalidRequestException;
import com.vpbank.dcp.auth.adapter.in.web.dto.request.CaptchaRequest;
import com.vpbank.dcp.auth.adapter.in.web.dto.response.CaptchaResponse;
import com.vpbank.dcp.auth.application.port.in.CaptchaChallenge;
import com.vpbank.dcp.auth.domain.model.UserName;
import org.springframework.http.ResponseEntity;

import java.util.Base64;

/** CAPTCHA wire ↔ use case. Static: no localized text is involved. */
public final class CaptchaWebMapper {
    private CaptchaWebMapper() {
    }

    public static UserName toUserName(CaptchaRequest request) {
        try {
            return new UserName(request.userName());
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public static ResponseEntity<ApiEnvelope<CaptchaResponse>> toResponse(CaptchaChallenge challenge) {
        return ResponseEntity.ok(ApiEnvelope.success(new CaptchaResponse(challenge.captchaId().value(),
                Base64.getEncoder().encodeToString(challenge.imagePng()), challenge.expiresAt())));
    }
}
