package com.vpbank.dcp.auth.domain.model;

import java.util.UUID;
import lombok.NonNull;

/** Identifier of one issued CAPTCHA challenge; single use, short-lived. */
public record CaptchaId(@NonNull UUID value) {

    public static CaptchaId random() {
        return new CaptchaId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
