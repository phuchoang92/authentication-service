package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.Map;

/**
 * {@code POST /api/ns/v1/login}. {@code tokenEncryptionKey} is the app's public P-256 JWK (DD 06);
 * {@code deviceId} and {@code platform} are required on MOBILE, {@code devicePublicKey} (P-256 JWK)
 * is optional; {@code captcha} is sent once a login answered 428 CAPTCHA_REQUIRED.
 */
public record LoginRequest(
        @NotBlank(message = "{auth.required}")
        @Pattern(regexp = "[A-Za-z0-9._-]{3,64}", message = "{auth.format}") String userName,
        @NotBlank(message = "{auth.required}") @Size(max = 128, message = "{auth.tooLong}") String password,
        @NotBlank(message = "{auth.required}") @Pattern(regexp = "MOBILE|WEB", message = "{auth.format}") String channel,
        @Pattern(regexp = "[A-Za-z0-9._-]{1,64}", message = "{auth.format}") String deviceId,
        @Pattern(regexp = "ANDROID|IOS", message = "{auth.format}") String platform,
        Map<String, Object> devicePublicKey,
        @NotNull(message = "{auth.required}") Map<String, Object> tokenEncryptionKey,
        @Valid CaptchaDto captcha) {

    public record CaptchaDto(
            @NotBlank(message = "{auth.required}") @Pattern(regexp = "[0-9a-fA-F-]{36}", message = "{auth.format}")
            String captchaId,
            @NotBlank(message = "{auth.required}") @Pattern(regexp = "[A-Za-z0-9]{4,8}", message = "{auth.format}")
            String answer) {
        @Override
        public String toString() {
            return "CaptchaDto[captchaId=" + captchaId + ", redacted]";
        }
    }

    @Override
    public String toString() {
        return "LoginRequest[userName=" + userName + ", channel=" + channel + ", redacted]";
    }
}
