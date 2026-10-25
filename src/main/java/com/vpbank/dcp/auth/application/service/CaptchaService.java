package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.result.CaptchaChallenge;
import com.vpbank.dcp.auth.application.port.in.IssueCaptchaUseCase;
import com.vpbank.dcp.auth.application.port.out.gateway.CaptchaGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.CaptchaGenerator.GeneratedCaptcha;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.model.CustomerAuthentication;
import com.vpbank.dcp.auth.application.port.out.repository.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Issues a CAPTCHA bound to the customer behind a user name. An unknown name still gets a real
 * challenge (bound to nobody), so timing and shape reveal nothing about account existence.
 */
@RequiredArgsConstructor
public final class CaptchaService implements IssueCaptchaUseCase {
    @NonNull private final CustomerAuthenticationRepository identities;
    @NonNull private final CaptchaGenerator generator;
    @NonNull private final CaptchaStore captchas;
    @NonNull private final Duration lifetime;
    @NonNull private final Clock clock;

    @Override
    public CaptchaChallenge issue(UserName userName) {
        CustomerId customerId = identities.findByUserName(userName).map(CustomerAuthentication::customerId).orElse(null);
        GeneratedCaptcha generated = generator.next();
        CaptchaId id = CaptchaId.random();
        Instant expiresAt = clock.instant().plus(lifetime);
        captchas.save(id, customerId, generated.answer(), expiresAt);
        return new CaptchaChallenge(id, generated.imagePng(), expiresAt);
    }
}
