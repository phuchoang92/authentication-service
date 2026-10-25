package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.gateway.CaptchaGenerator;
import com.vpbank.dcp.auth.application.port.out.model.CustomerAuthentication;
import com.vpbank.dcp.auth.application.result.CaptchaChallenge;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.PasswordLockout;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class CaptchaServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00Z");
    private final InMemoryCustomerAuthenticationRepository identities = new InMemoryCustomerAuthenticationRepository();
    private final InMemoryCaptchaStore captchas = new InMemoryCaptchaStore();
    private final CaptchaGenerator generator = () -> new CaptchaGenerator.GeneratedCaptcha(new CaptchaAnswer("AB3CD"), new byte[]{1, 2});
    private final CaptchaService service = new CaptchaService(identities, generator, captchas, Duration.ofMinutes(5),
            Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void bindsTheChallengeToTheCustomerBehindTheUserName() {
        identities.rows.put(new CustomerId("90359"), CustomerAuthentication.builder().customerId(new CustomerId("90359"))
                .userName(new UserName("alice")).identityIssuer("iss").identitySubject("sub").status("ACTIVE")
                .lockout(PasswordLockout.none()).version(0).build());

        CaptchaChallenge challenge = service.issue(new UserName("ALICE"));

        assertThat(challenge.imagePng()).containsExactly(1, 2);
        assertThat(challenge.expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(5)));
        assertThat(captchas.challenges.get(challenge.captchaId()).customerId()).isEqualTo(new CustomerId("90359"));
        assertThat(captchas.consume(challenge.captchaId(), new CustomerId("90359"), new CaptchaAnswer("ab3cd"))).isTrue();
        assertThat(challenge.toString()).doesNotContain("AB3CD");
    }

    @Test
    void anUnknownUserNameStillGetsAChallengeThatMatchesNobody() {
        CaptchaChallenge challenge = service.issue(new UserName("nobody"));

        assertThat(challenge.imagePng()).isNotEmpty();
        assertThat(captchas.challenges.get(challenge.captchaId()).customerId()).isNull();
        assertThat(captchas.consume(challenge.captchaId(), new CustomerId("90359"), new CaptchaAnswer("AB3CD"))).isFalse();
    }
}
