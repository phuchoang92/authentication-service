package com.vpbank.dcp.auth.domain.model;

import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/** What the customer typed from the image: 4–8 letters/digits, compared case-insensitively. Never logged. */
public record CaptchaAnswer(String value) {
    private static final Pattern FORMAT = Pattern.compile("[A-Za-z0-9]{4,8}");

    public CaptchaAnswer {
        Objects.requireNonNull(value, "value");
        if (!FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("CAPTCHA answer has an invalid format");
        }
    }

    public String normalized() {
        return value.toUpperCase(Locale.ROOT);
    }

    @Override
    public String toString() {
        return "CaptchaAnswer[redacted]";
    }
}
