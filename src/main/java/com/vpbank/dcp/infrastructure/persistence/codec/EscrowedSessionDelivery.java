package com.vpbank.dcp.infrastructure.persistence.codec;

import java.util.Objects;

/** Only the App-encrypted token and its delivery metadata are stored. */
public record EscrowedSessionDelivery(String tokenEnvelope, String receipt, String dpopNonce) {
    public EscrowedSessionDelivery {
        Objects.requireNonNull(tokenEnvelope);
        Objects.requireNonNull(receipt);
        Objects.requireNonNull(dpopNonce);
    }

    @Override
    public String toString() { return "EscrowedSessionDelivery[redacted]"; }
}
