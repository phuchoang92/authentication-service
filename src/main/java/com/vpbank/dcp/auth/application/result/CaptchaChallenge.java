package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.model.CaptchaId;
import java.time.Instant;
import java.util.Objects;

/** What the app shows: the challenge ID to send back and the PNG to display. */
public record CaptchaChallenge(CaptchaId captchaId, byte[] imagePng, Instant expiresAt) {
    public CaptchaChallenge {
        Objects.requireNonNull(captchaId, "captchaId");
        Objects.requireNonNull(imagePng, "imagePng");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }

    @Override
    public String toString() {
        return "CaptchaChallenge[captchaId=" + captchaId + ", expiresAt=" + expiresAt + "]";
    }
}
