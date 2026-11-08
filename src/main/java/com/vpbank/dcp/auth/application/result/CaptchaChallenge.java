package com.vpbank.dcp.auth.application.result;

import java.time.Instant;
import lombok.NonNull;

/**
 * The challenge a login answers with {@code 428 CAPTCHA_REQUIRED}: the image to show and how long the customer
 * has to answer it. No ID: the challenge is the customer's one open challenge, found again by the user name.
 */
public record CaptchaChallenge(@NonNull byte[] imagePng, @NonNull Instant expiresAt) {
    public CaptchaChallenge {
        if (imagePng.length == 0) {
            throw new IllegalArgumentException("A challenge has an image");
        }
        imagePng = imagePng.clone();
    }

    @Override
    public byte[] imagePng() {
        return imagePng.clone();
    }

    @Override
    public String toString() {
        return "CaptchaChallenge[expiresAt=" + expiresAt + ", redacted]";
    }
}
