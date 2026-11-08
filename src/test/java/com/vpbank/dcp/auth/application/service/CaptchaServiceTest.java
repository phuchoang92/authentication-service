package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.gateway.CaptchaGenerator;
import com.vpbank.dcp.auth.application.result.CaptchaChallenge;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class CaptchaServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00Z");
    private static final CustomerId ALICE = new CustomerId("90359");
    private final InMemoryCaptchaStore captchas = new InMemoryCaptchaStore();
    private final CaptchaGenerator generator =
            () -> new CaptchaGenerator.GeneratedCaptcha(new CaptchaAnswer("AB3CD"), new byte[]{1, 2});
    private final CaptchaService service =
            new CaptchaService(generator, captchas, Duration.ofMinutes(5), Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void issuesTheCustomersChallengeAndTheAnswerSolvesItOnce() {
        CaptchaChallenge challenge = service.issueFor(ALICE);

        assertThat(challenge.imagePng()).containsExactly(1, 2);
        assertThat(challenge.expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(5)));
        assertThat(challenge.toString()).doesNotContain("AB3CD");
        assertThat(captchas.challenges).containsOnlyKeys(ALICE);

        assertThat(service.solved(new CustomerId("77777"), new CaptchaAnswer("ab3cd"))).isFalse(); // not this customer's
        assertThat(service.solved(ALICE, new CaptchaAnswer("ab3cd"))).isTrue();
        assertThat(service.solved(ALICE, new CaptchaAnswer("ab3cd"))).isFalse(); // consumed
    }

    @Test
    void aNewChallengeReplacesTheCustomersEarlierOne() {
        service.issueFor(ALICE);
        CaptchaService nextAnswer = new CaptchaService(
                () -> new CaptchaGenerator.GeneratedCaptcha(new CaptchaAnswer("XY7ZW"), new byte[]{3}),
                captchas, Duration.ofMinutes(5), Clock.fixed(NOW, ZoneOffset.UTC));

        nextAnswer.issueFor(ALICE);

        assertThat(captchas.challenges).hasSize(1);
        assertThat(service.solved(ALICE, new CaptchaAnswer("AB3CD"))).isFalse(); // the earlier answer is gone
        assertThat(captchas.challenges).isEmpty(); // and the wrong answer consumed the new challenge
    }
}
