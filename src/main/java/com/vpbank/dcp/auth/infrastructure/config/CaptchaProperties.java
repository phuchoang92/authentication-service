package com.vpbank.dcp.auth.infrastructure.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** CAPTCHA answers are stored as a keyed HMAC, never in clear: this is that key (Base64, at least 32 bytes). */
@Validated
@ConfigurationProperties(prefix = "auth.captcha")
public record CaptchaProperties(@NotBlank String answerHmacKeyBase64) {

    @Override
    public String toString() {
        return "CaptchaProperties[redacted]";
    }
}
