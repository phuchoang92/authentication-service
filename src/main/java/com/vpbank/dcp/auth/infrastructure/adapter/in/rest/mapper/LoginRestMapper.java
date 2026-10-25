package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import com.vpbank.dcp.auth.application.command.CaptchaSolution;
import com.vpbank.dcp.auth.application.command.LoginCommand;
import com.vpbank.dcp.auth.application.result.LoginResult;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.Password;
import com.vpbank.dcp.auth.domain.model.UserName;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.InvalidRequestException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.ErrorCodes;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.LoginRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.LoginResponse;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/** Login wire ↔ use case. The JWK arrives as a JSON object and is handed on as text; the sealer validates it. */
@RequiredArgsConstructor
public final class LoginRestMapper {
    @NonNull private final ErrorMessages errorMessages;

    public LoginCommand toCommand(LoginRequest request) {
        try {
            // Device fields are optional on WEB; the use case checks they are present together on MOBILE.
            DeviceId deviceId = request.deviceId() == null ? null : new DeviceId(request.deviceId());
            DevicePlatform platform = request.platform() == null ? null : DevicePlatform.valueOf(request.platform());
            String devicePublicKey = request.devicePublicKey() == null ? null : json(request.devicePublicKey());
            CaptchaSolution captchaSolution = request.captcha() == null ? null : toCaptchaSolution(request.captcha());

            return LoginCommand.builder()
                    .userName(new UserName(request.userName()))
                    .password(new Password(request.password().toCharArray()))
                    .channel(Channel.valueOf(request.channel()))
                    .deviceId(deviceId)
                    .platform(platform)
                    .devicePublicKey(devicePublicKey)
                    .tokenEncryptionKey(json(request.tokenEncryptionKey()))
                    .captcha(captchaSolution)
                    .build();
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public ResponseEntity<ApiEnvelope<LoginResponse>> toResponse(LoginResult result) {
        return switch (result) {
            case LoginResult.Authenticated authenticated -> authenticated(authenticated);
            case LoginResult.InvalidCredentials() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.INVALID_CREDENTIALS);
            case LoginResult.AccountNotReady() ->
                    errorMessages.failure(HttpStatus.FORBIDDEN, ErrorCodes.ACCOUNT_NOT_READY);
            case LoginResult.AccountLocked() ->
                    errorMessages.failure(HttpStatus.LOCKED, ErrorCodes.ACCOUNT_LOCKED);
            case LoginResult.CaptchaRequired() ->
                    errorMessages.failure(HttpStatus.PRECONDITION_REQUIRED, ErrorCodes.CAPTCHA_REQUIRED);
            case LoginResult.Unavailable() ->
                    errorMessages.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.LOGIN_UNAVAILABLE);
        };
    }

    private static CaptchaSolution toCaptchaSolution(LoginRequest.CaptchaDto captcha) {
        CaptchaId captchaId = new CaptchaId(UUID.fromString(captcha.captchaId()));
        CaptchaAnswer captchaAnswer = new CaptchaAnswer(captcha.answer());
        return new CaptchaSolution(captchaId, captchaAnswer);
    }

    /** 201: a session (full or restricted) was created; the status tells the app which. */
    private static ResponseEntity<ApiEnvelope<LoginResponse>> authenticated(LoginResult.Authenticated authenticated) {
        LoginResponse response = new LoginResponse(
                authenticated.tokenEnvelope(),
                authenticated.status().name(),
                authenticated.idleExpiresAt(),
                authenticated.absoluteExpiresAt());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiEnvelope.success(response));
    }

    /** Minimal JSON for a flat JWK object (strings only); anything else is not a public JWK we accept. */
    static String json(Map<String, Object> jwk) {
        boolean flat = jwk.values().stream().allMatch(value -> value instanceof String);
        if (!flat) {
            throw new IllegalArgumentException("tokenEncryptionKey must be a flat JWK object");
        }
        return jwk.entrySet().stream()
                .map(member -> "\"" + escape(member.getKey()) + "\":\"" + escape((String) member.getValue()) + "\"")
                .collect(Collectors.joining(",", "{", "}"));
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
