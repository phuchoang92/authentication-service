package com.vpbank.dcp.core.domain.customer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class CustomerFreshnessPolicyTest {
    @Test
    void expiresAtTheExactConfiguredBoundary() {
        var policy = new CustomerFreshnessPolicy(Duration.ofMillis(30_000));
        Instant checkedAt = Instant.parse("2026-10-12T00:00:00.123456Z");
        Instant boundary = checkedAt.plusSeconds(30);
        assertThat(policy.validUntil(checkedAt)).isEqualTo(boundary);
        assertThat(policy.isFresh(checkedAt, boundary.minusNanos(1))).isTrue();
        assertThat(policy.isFresh(checkedAt, boundary)).isFalse();
        assertThat(policy.isFresh(checkedAt, boundary.plusNanos(1))).isFalse();
    }

    @Test
    void rejectsNonpositiveMaximumAge() {
        assertThatThrownBy(() -> new CustomerFreshnessPolicy(Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CustomerFreshnessPolicy(Duration.ofMillis(-1)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
