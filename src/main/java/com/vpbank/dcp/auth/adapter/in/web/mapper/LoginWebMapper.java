package com.vpbank.dcp.auth.adapter.in.web.mapper;

import com.vpbank.dcp.auth.adapter.in.web.common.ApiEnvelope;
import com.vpbank.dcp.auth.adapter.in.web.common.ErrorCodes;
import com.vpbank.dcp.auth.adapter.in.web.common.ErrorMessages;
import com.vpbank.dcp.auth.adapter.in.web.common.InvalidRequestException;
import com.vpbank.dcp.auth.adapter.in.web.dto.request.LoginRequest;
import com.vpbank.dcp.auth.adapter.in.web.dto.response.LoginResponse;
import com.vpbank.dcp.auth.application.port.in.CaptchaSolution;
import com.vpbank.dcp.auth.application.port.in.LoginCommand;
import com.vpbank.dcp.auth.application.port.in.LoginResult;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.Password;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.stream.Collectors;

/** Login wire ↔ use case. The JWK arrives as a JSON object and is handed on as text; the sealer validates it. */
@RequiredArgsConstructor
public final class LoginWebMapper {
    @NonNull private final ErrorMessages errors;

    public LoginCommand toCommand(LoginRequest request) {
        try {
            return LoginCommand.builder()
                    .userName(new UserName(request.userName()))
                    .password(new Password(request.password().toCharArray()))
                    .channel(Channel.valueOf(request.channel()))
                    .deviceId(request.deviceId() == null ? null : new DeviceId(request.deviceId()))
                    .tokenEncryptionKey(json(request.tokenEncryptionKey()))
                    .captcha(request.captcha() == null ? null : new CaptchaSolution(
                            new CaptchaId(java.util.UUID.fromString(request.captcha().captchaId())),
                            new CaptchaAnswer(request.captcha().answer())))
                    .build();
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public ResponseEntity<ApiEnvelope<LoginResponse>> toResponse(LoginResult result) {
        return switch (result) {
            case LoginResult.Authenticated ok -> ResponseEntity.status(HttpStatus.CREATED).body(ApiEnvelope.success(
                    new LoginResponse(ok.tokenEnvelope(), ok.status().name(), ok.idleExpiresAt(), ok.absoluteExpiresAt())));
            case LoginResult.InvalidCredentials() -> errors.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.INVALID_CREDENTIALS);
            case LoginResult.AccountNotReady() -> errors.failure(HttpStatus.FORBIDDEN, ErrorCodes.ACCOUNT_NOT_READY);
            case LoginResult.AccountLocked() -> errors.failure(HttpStatus.LOCKED, ErrorCodes.ACCOUNT_LOCKED);
            case LoginResult.CaptchaRequired() ->
                    errors.failure(HttpStatus.PRECONDITION_REQUIRED, ErrorCodes.CAPTCHA_REQUIRED);
            case LoginResult.Unavailable() -> errors.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.LOGIN_UNAVAILABLE);
        };
    }

    /** Minimal JSON for a flat JWK object (strings only); anything else is not a public JWK we accept. */
    static String json(Map<String, Object> jwk) {
        if (jwk.values().stream().anyMatch(v -> !(v instanceof String))) {
            throw new IllegalArgumentException("tokenEncryptionKey must be a flat JWK object");
        }
        return jwk.entrySet().stream()
                .map(e -> "\"" + escape(e.getKey()) + "\":\"" + escape((String) e.getValue()) + "\"")
                .collect(Collectors.joining(",", "{", "}"));
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
