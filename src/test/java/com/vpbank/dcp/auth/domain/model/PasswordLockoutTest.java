package com.vpbank.dcp.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

class PasswordLockoutTest {
    private static final Instant T0 = Instant.parse("2026-10-25T10:00:00Z");
    private final LockoutPolicy policy = LockoutPolicy.standard();

    @Test
    void escalatesCaptchaThenFifteenMinutesThenADayThenPermanent() {
        PasswordLockout one = PasswordLockout.none().afterFailure(T0, policy);
        PasswordLockout two = one.afterFailure(T0, policy);
        PasswordLockout three = two.afterFailure(T0, policy);
        PasswordLockout four = three.afterFailure(T0.plus(Duration.ofMinutes(16)), policy);
        PasswordLockout five = four.afterFailure(T0.plus(Duration.ofHours(25)), policy);

        assertThat(one.captchaRequired(policy)).isFalse();
        assertThat(two.captchaRequired(policy)).isTrue();
        assertThat(two.isLocked(T0)).isFalse();
        assertThat(three.status()).isEqualTo(PasswordStatus.LOCKED);
        assertThat(three.lockedUntil()).isEqualTo(T0.plus(Duration.ofMinutes(15)));
        assertThat(three.isLocked(T0.plus(Duration.ofMinutes(14)))).isTrue();
        assertThat(three.isLocked(T0.plus(Duration.ofMinutes(15)))).isFalse();
        assertThat(four.failedCount()).isEqualTo(4);
        assertThat(four.lockedUntil()).isEqualTo(T0.plus(Duration.ofMinutes(16)).plus(Duration.ofHours(24)));
        assertThat(five.status()).isEqualTo(PasswordStatus.PERMANENTLY_LOCKED);
        assertThat(five.isLocked(T0.plus(Duration.ofDays(400)))).isTrue();
        assertThat(five.lockedUntil()).isNull();
    }

    @Test
    void anExpiredLockDoesNotResetTheCountOnlyASuccessDoes() {
        PasswordLockout three = PasswordLockout.none().afterFailure(T0, policy).afterFailure(T0, policy).afterFailure(T0, policy);
        assertThat(three.afterFailure(T0.plus(Duration.ofHours(1)), policy).failedCount()).isEqualTo(4);
        assertThat(three.reset()).isEqualTo(PasswordLockout.none());
        assertThat(three.reset().captchaRequired(policy)).isFalse();
    }

    @Test
    void invariantsAndPolicyAreChecked() {
        assertThatThrownBy(() -> new PasswordLockout(PasswordStatus.LOCKED, 3, null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PasswordLockout(PasswordStatus.ACTIVE, 0, T0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PasswordLockout(PasswordStatus.ACTIVE, -1, null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LockoutPolicy(2, new TreeMap<>(java.util.Map.of(5, Duration.ofMinutes(1))), 5))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LockoutPolicy(0, new TreeMap<>(java.util.Map.of(3, Duration.ofMinutes(1))), 5))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
