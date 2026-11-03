package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import com.vpbank.dcp.auth.application.command.CaptchaSolution;
import com.vpbank.dcp.auth.application.command.LoginCommand;
import com.vpbank.dcp.auth.application.result.LoginResult;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DeviceProof;
import com.vpbank.dcp.auth.domain.model.Password;
import com.vpbank.dcp.auth.domain.model.UserName;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.InvalidRequestException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.JwkJson;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.DeviceHeaders;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.ErrorCodes;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.LoginRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.LoginResponse;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.regex.Pattern;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * Login wire ↔ use case. The credentials and the token key come in the body (the JWK arrives as a JSON
 * object and is handed on as text; the sealer validates it); the channel, device and proof come as headers
 * ({@link DeviceHeaders}), checked for shape here and refused with {@code 400} like a bad body.
 */
@RequiredArgsConstructor
public final class LoginRestMapper {
    private static final Pattern DEVICE_ID = Pattern.compile("[A-Za-z0-9._-]{1,64}");
    private static final Pattern EPOCH_SECONDS = Pattern.compile("[0-9]{1,12}");
    private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+");
    private static final int MAX_PROOF_LENGTH = 6000;

    @NonNull private final ErrorMessages errorMessages;

    public LoginCommand toCommand(HttpHeaders headers, LoginRequest request) {
        try {
            // Device headers are optional on WEB; the use case checks they are present together on MOBILE.
            Channel channel = Channel.valueOf(required(headers, DeviceHeaders.CHANNEL));
            String deviceIdHeader = headers.getFirst(DeviceHeaders.DEVICE_ID);
            String deviceOsHeader = headers.getFirst(DeviceHeaders.DEVICE_OS);
            String deviceProofHeader = headers.getFirst(DeviceHeaders.DEVICE_PROOF);
            DeviceId deviceId = deviceIdHeader == null ? null : toDeviceId(deviceIdHeader);
            DevicePlatform platform = deviceOsHeader == null ? null : DevicePlatform.valueOf(deviceOsHeader);
            DeviceProof deviceProof = deviceProofHeader == null ? null : toDeviceProof(deviceProofHeader);
            CaptchaSolution captchaSolution = request.captcha() == null ? null : toCaptchaSolution(request.captcha());

            return LoginCommand.builder()
                    .userName(new UserName(request.userName()))
                    .password(new Password(request.password().toCharArray()))
                    .channel(channel)
                    .deviceId(deviceId)
                    .platform(platform)
                    .deviceProof(deviceProof)
                    .tokenEncryptionKey(JwkJson.toJson(request.tokenEncryptionKey()))
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

    private static String required(HttpHeaders headers, String name) {
        String value = headers.getFirst(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    private static DeviceId toDeviceId(String header) {
        if (!DEVICE_ID.matcher(header).matches()) {
            throw new IllegalArgumentException(DeviceHeaders.DEVICE_ID + " has an invalid format");
        }
        return new DeviceId(header);
    }

    /** {@code <issuedAt>.<nonce>.<signature>}: the shape only; whether it verifies is the use case's answer. */
    private static DeviceProof toDeviceProof(String header) {
        String[] parts = header.split("\\.", -1);
        boolean wellFormed = header.length() <= MAX_PROOF_LENGTH
                && parts.length == 3
                && EPOCH_SECONDS.matcher(parts[0]).matches()
                && BASE64URL.matcher(parts[1]).matches()
                && BASE64URL.matcher(parts[2]).matches();
        if (!wellFormed) {
            throw new IllegalArgumentException(DeviceHeaders.DEVICE_PROOF + " has an invalid format");
        }
        Instant issuedAt = Instant.ofEpochSecond(Long.parseLong(parts[0]));
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        return new DeviceProof(issuedAt, parts[1], signature);
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
}
