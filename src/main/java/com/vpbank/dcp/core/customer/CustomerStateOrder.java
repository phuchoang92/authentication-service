package com.vpbank.dcp.core.customer;

import java.util.Objects;

/** A block watermark cannot be erased by a later ELIGIBLE state or an old event. */
public final class CustomerStateOrder {

    public CustomerStateDecision compare(CustomerAuthenticationState current,
                                         CustomerAuthenticationState incoming) {
        Objects.requireNonNull(current, "current");
        Objects.requireNonNull(incoming, "incoming");
        if (!current.customerNumber().equals(incoming.customerNumber())) {
            return CustomerStateDecision.CONFLICT;
        }
        if (incoming.lastAccessBlockVersion() > current.lastAccessBlockVersion()) {
            return CustomerStateDecision.BLOCK_WATERMARK_ADVANCED;
        }
        if (incoming.lastAccessBlockVersion() < current.lastAccessBlockVersion()) {
            return CustomerStateDecision.STALE;
        }
        if (incoming.statusVersion() < current.statusVersion()) {
            return CustomerStateDecision.STALE;
        }
        if (incoming.statusVersion() == current.statusVersion()) {
            return incoming.status() == current.status()
                    ? CustomerStateDecision.STALE : CustomerStateDecision.CONFLICT;
        }
        return CustomerStateDecision.ACCEPT;
    }
}
