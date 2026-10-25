package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import com.vpbank.dcp.auth.application.result.CaptchaChallenge;
import com.vpbank.dcp.auth.domain.model.UserName;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.InvalidRequestException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.CaptchaRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.CaptchaResponse;
import java.util.Base64;
import org.springframework.http.ResponseEntity;

/** CAPTCHA wire ↔ use case. Static: no localized text is involved. */
public final class CaptchaRestMapper {
    private CaptchaRestMapper() {
    }

    public static UserName toUserName(CaptchaRequest request) {
        try {
            return new UserName(request.userName());
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public static ResponseEntity<ApiEnvelope<CaptchaResponse>> toResponse(CaptchaChallenge challenge) {
        String imagePngBase64 = Base64.getEncoder().encodeToString(challenge.imagePng());
        CaptchaResponse response = new CaptchaResponse(
                challenge.captchaId().value(),
                imagePngBase64,
                challenge.expiresAt());
        return ResponseEntity.ok(ApiEnvelope.success(response));
    }
}
