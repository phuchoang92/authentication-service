package com.vpbank.dcp.core.customer;

import java.util.Objects;

/** A login snapshot cannot clear a newer local block or skipped block watermark. */
public final class CustomerOwnerPolicy {

    private final CustomerStateOrder order = new CustomerStateOrder();

    public CustomerOwnerDecision decide(CustomerAuthenticationState current,
                                        CustomerAuthenticationState incoming) {
        Objects.requireNonNull(current, "current");
        Objects.requireNonNull(incoming, "incoming");
        CustomerStateDecision state = order.compare(current, incoming);
        if (state == CustomerStateDecision.CONFLICT) {
            return CustomerOwnerDecision.CONFLICT;
        }
        if (state == CustomerStateDecision.BLOCK_WATERMARK_ADVANCED
                || incoming.statusVersion() < current.statusVersion()
                || incoming.lastAccessBlockVersion() < current.lastAccessBlockVersion()
                || !current.status().allowsLogin()) {
            return CustomerOwnerDecision.RECONCILIATION_REQUIRED;
        }
        return CustomerOwnerDecision.ACCEPT;
    }
}
