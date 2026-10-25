package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.in.IssueCaptchaUseCase;
import com.vpbank.dcp.auth.application.port.out.gateway.CaptchaGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.CaptchaGenerator.GeneratedCaptcha;
import com.vpbank.dcp.auth.application.port.out.model.CustomerAuthentication;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.repository.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.result.CaptchaChallenge;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Issues a CAPTCHA bound to the customer behind a user name. An unknown name still gets a real
 * challenge (bound to nobody), so timing and shape reveal nothing about account existence.
 */
@RequiredArgsConstructor
public final class CaptchaService implements IssueCaptchaUseCase {
    @NonNull private final CustomerAuthenticationRepository customerAuthenticationRepository;
    @NonNull private final CaptchaGenerator captchaGenerator;
    @NonNull private final CaptchaStore captchaStore;
    @NonNull private final Duration captchaLifetime;
    @NonNull private final Clock clock;

    @Override
    public CaptchaChallenge issue(UserName userName) {
        // Null when the name is unknown: the challenge is then bound to nobody and solves no login.
        CustomerId boundCustomerId = customerAuthenticationRepository.findByUserName(userName)
                .map(CustomerAuthentication::customerId)
                .orElse(null);

        GeneratedCaptcha generatedCaptcha = captchaGenerator.next();
        CaptchaId captchaId = CaptchaId.random();
        Instant expiresAt = clock.instant().plus(captchaLifetime);

        captchaStore.save(captchaId, boundCustomerId, generatedCaptcha.answer(), expiresAt);

        return new CaptchaChallenge(captchaId, generatedCaptcha.imagePng(), expiresAt);
    }
}
