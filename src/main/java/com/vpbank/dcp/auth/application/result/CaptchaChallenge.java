package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.model.CaptchaId;
import java.time.Instant;
import lombok.NonNull;

/** What the app shows: the challenge ID to send back and the PNG to display. */
public record CaptchaChallenge(@NonNull CaptchaId captchaId, @NonNull byte[] imagePng, @NonNull Instant expiresAt) {
    @Override
    public String toString() {
        return "CaptchaChallenge[captchaId=" + captchaId + ", expiresAt=" + expiresAt + "]";
    }
}
