package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;
import java.util.UUID;

/** Identifier of one issued CAPTCHA challenge; single use, short-lived. */
public record CaptchaId(UUID value) {
    public CaptchaId {
        Objects.requireNonNull(value, "value");
    }

    public static CaptchaId random() {
        return new CaptchaId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
