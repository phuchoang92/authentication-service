package com.vpbank.dcp.core.session;

import java.time.Instant;
import java.util.Objects;

/** Exact protected response and its fixed recovery deadline; never a plaintext token. */
public record SessionDelivery(String tokenEnvelope, String receipt, String dpopNonce,
                              Instant deliveryDeadline) {
    public SessionDelivery {
        Objects.requireNonNull(tokenEnvelope);
        Objects.requireNonNull(receipt);
        Objects.requireNonNull(dpopNonce);
        Objects.requireNonNull(deliveryDeadline);
    }

    @Override
    public String toString() {
        return "SessionDelivery[redacted]";
    }
}
