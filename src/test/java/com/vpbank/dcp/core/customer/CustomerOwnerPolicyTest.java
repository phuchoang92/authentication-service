package com.vpbank.dcp.core.customer;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class CustomerOwnerPolicyTest {

    private final CustomerOwnerPolicy policy = new CustomerOwnerPolicy();
    private final Instant now = Instant.parse("2026-10-11T10:00:00Z");

    @Test
    void newerVersionWithRegressedBlockWatermarkCannotAuthorize() {
        CustomerAuthenticationState current = state(CustomerStatus.ELIGIBLE, 3, 2);
        CustomerAuthenticationState incoming = state(CustomerStatus.ELIGIBLE, 4, 0);

        assertThat(policy.decide(current, incoming))
                .isEqualTo(CustomerOwnerDecision.RECONCILIATION_REQUIRED);
    }

    @Test
    void sameVersionAndWatermarkCanRefreshEligibleSnapshot() {
        CustomerAuthenticationState current = state(CustomerStatus.ELIGIBLE, 3, 2);
        CustomerAuthenticationState incoming = state(CustomerStatus.ELIGIBLE, 3, 2);

        assertThat(policy.decide(current, incoming)).isEqualTo(CustomerOwnerDecision.ACCEPT);
    }

    private CustomerAuthenticationState state(CustomerStatus status, long version, long block) {
        return new CustomerAuthenticationState(new CustomerNumber("CUST-1"), status, version, block, now);
    }
}
