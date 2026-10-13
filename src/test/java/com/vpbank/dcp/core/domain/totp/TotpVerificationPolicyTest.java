package com.vpbank.dcp.core.domain.totp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class TotpVerificationPolicyTest {

    @Test
    void acceptsExplicitBoundedPolicy() {
        TotpVerificationPolicy policy = new TotpVerificationPolicy(3, Duration.ofMinutes(15));

        assertThat(policy.maximumFailures()).isEqualTo(3);
        assertThat(policy.lockDuration()).isEqualTo(Duration.ofMinutes(15));
    }

    @Test
    void rejectsMissingOrNonPositiveBudget() {
        assertThatThrownBy(() -> new TotpVerificationPolicy(0, Duration.ofMinutes(15)))
                .isInstanceOf(InvalidTotpVerificationPolicyException.class);
        assertThatThrownBy(() -> new TotpVerificationPolicy(5, Duration.ZERO))
                .isInstanceOf(InvalidTotpVerificationPolicyException.class);
        assertThatThrownBy(() -> new TotpVerificationPolicy(5, null))
                .isInstanceOf(NullPointerException.class);
    }
}
