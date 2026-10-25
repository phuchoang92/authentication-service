package com.vpbank.dcp.core.customer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class CustomerStateOrderTest {

    private final CustomerStateOrder order = new CustomerStateOrder();
    private final Instant checkedAt = Instant.parse("2026-10-11T03:10:00Z");

    @Test
    void laterEligibleSnapshotStillExposesAnUnseenBlock() {
        var current = state(CustomerStatus.ELIGIBLE, 40, 0);
        var incoming = state(CustomerStatus.ELIGIBLE, 43, 42);

        assertEquals(CustomerStateDecision.BLOCK_WATERMARK_ADVANCED,
                order.compare(current, incoming));
    }

    @Test
    void olderEventCannotLowerKnownBlockWatermark() {
        var current = state(CustomerStatus.ELIGIBLE, 43, 42);
        var incoming = state(CustomerStatus.BLOCKED, 42, 42);

        assertEquals(CustomerStateDecision.STALE, order.compare(current, incoming));
    }

    @Test
    void equalVersionWithDifferentStatusIsConflict() {
        var current = state(CustomerStatus.ELIGIBLE, 42, 42);
        var incoming = state(CustomerStatus.BLOCKED, 42, 42);

        assertEquals(CustomerStateDecision.CONFLICT, order.compare(current, incoming));
    }

    @Test
    void invalidBlockingWatermarkFailsClosed() {
        assertThrows(InvalidCustomerStateException.class,
                () -> state(CustomerStatus.BLOCKED, 42, 41));
    }

    private CustomerAuthenticationState state(CustomerStatus status, long version, long block) {
        return new CustomerAuthenticationState(new CustomerNumber("CUST-001"), status, version, block, checkedAt);
    }
}
