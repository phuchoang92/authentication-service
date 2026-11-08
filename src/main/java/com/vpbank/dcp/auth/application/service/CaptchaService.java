package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.gateway.CaptchaGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.CaptchaGenerator.GeneratedCaptcha;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.application.result.CaptchaChallenge;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * The CAPTCHA of a login (decided 2026-11-08): once a customer has failed often enough, the login itself answers
 * with a challenge, and the next login carries only the answer. A customer has one open challenge at a time; a
 * new one replaces it, and any answer, right or wrong, consumes it.
 */
@RequiredArgsConstructor
public final class CaptchaService {
    @NonNull private final CaptchaGenerator captchaGenerator;
    @NonNull private final CaptchaStore captchaStore;
    @NonNull private final Duration captchaLifetime;
    @NonNull private final Clock clock;

    /** A fresh challenge for this customer, replacing any earlier one. */
    public CaptchaChallenge issueFor(CustomerId customerId) {
        GeneratedCaptcha generated = captchaGenerator.next();
        Instant expiresAt = clock.instant().plus(captchaLifetime);
        captchaStore.issue(customerId, generated.answer(), expiresAt);
        return new CaptchaChallenge(generated.imagePng(), expiresAt);
    }

    /** Consumes the customer's challenge; true only when it was live and this is its answer. */
    public boolean solved(CustomerId customerId, CaptchaAnswer answer) {
        return captchaStore.consume(customerId, answer);
    }
}
