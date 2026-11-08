package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Map;

/**
 * {@code POST /api/ns/v1/login}: the body carries the credentials and the app's public P-256 token key
 * (DD 06); the channel, the installation and the device proof travel as headers
 * ({@link com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.DeviceHeaders}). {@code captchaAnswer}
 * answers the challenge a previous login handed out with 428 CAPTCHA_REQUIRED (its headers).
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

        @Pattern(regexp = "[A-Za-z0-9]{4,8}", message = "{auth.format}")
        String captchaAnswer) {

    @Override
    public String toString() {
        return "LoginRequest[userName=" + userName + ", redacted]";
    }
}
