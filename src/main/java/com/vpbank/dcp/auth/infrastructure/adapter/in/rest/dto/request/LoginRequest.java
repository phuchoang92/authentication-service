package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Map;

/**
 * {@code POST /api/ns/v1/login}: the body carries the credentials and the app's public P-256 token key
 * (DD 06); the channel, the installation and the device proof travel as headers
 * ({@link com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.DeviceHeaders}). {@code captcha} is
 * sent once a login answered 428 CAPTCHA_REQUIRED.
 */
public record LoginRequest(

        @NotBlank(message = "{auth.required}")
        @Pattern(regexp = "[A-Za-z0-9._-]{3,64}", message = "{auth.format}")
        String userName,

        @NotBlank(message = "{auth.required}")
        @Size(max = 128, message = "{auth.tooLong}")
        String password,

        @NotNull(message = "{auth.required}")
        Map<String, Object> tokenEncryptionKey,

        @Valid
        CaptchaDto captcha) {

    public record CaptchaDto(
            @NotBlank(message = "{auth.required}")
            @Pattern(regexp = "[0-9a-fA-F-]{36}", message = "{auth.format}")
            String captchaId,
            @NotBlank(message = "{auth.required}")
            @Pattern(regexp = "[A-Za-z0-9]{4,8}", message = "{auth.format}")
            String answer) {
        @Override
        public String toString() {
            return "CaptchaDto[captchaId=" + captchaId + ", redacted]";
        }
    }

    @Override
    public String toString() {
        return "LoginRequest[userName=" + userName + ", redacted]";
    }
}
