package com.vpbank.dcp.auth.adapter.in.web.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Map;

/** {@code POST /api/ns/v1/login}. {@code tokenEncryptionKey} is the app's public P-256 JWK (DD 06). */
public record LoginRequest(
        @NotBlank(message = "{auth.required}")
        @Pattern(regexp = "[A-Za-z0-9._-]{3,64}", message = "{auth.format}") String userName,
        @NotBlank(message = "{auth.required}") @Size(max = 128, message = "{auth.tooLong}") String password,
        @NotBlank(message = "{auth.required}") @Pattern(regexp = "MOBILE|WEB", message = "{auth.format}") String channel,
        @Pattern(regexp = "[A-Za-z0-9._-]{1,64}", message = "{auth.format}") String deviceId,
        @NotNull(message = "{auth.required}") Map<String, Object> tokenEncryptionKey) {

    @Override
    public String toString() {
        return "LoginRequest[userName=" + userName + ", channel=" + channel + ", redacted]";
    }
}
