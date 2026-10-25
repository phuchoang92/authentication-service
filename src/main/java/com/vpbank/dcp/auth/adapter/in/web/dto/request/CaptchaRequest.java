package com.vpbank.dcp.auth.adapter.in.web.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/** {@code POST /api/ns/v1/login/captcha}: which user name the next login will be for. */
public record CaptchaRequest(
        @NotBlank(message = "{auth.required}")
        @Pattern(regexp = "[A-Za-z0-9._-]{3,64}", message = "{auth.format}") String userName) { }
