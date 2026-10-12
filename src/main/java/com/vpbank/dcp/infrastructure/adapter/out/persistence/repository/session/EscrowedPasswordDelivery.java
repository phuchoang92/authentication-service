package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.session;

import java.util.Objects;

/** Only the App-encrypted token and its delivery metadata are stored. */
public record EscrowedPasswordDelivery(String tokenEnvelope, String receipt, String dpopNonce) {
    public EscrowedPasswordDelivery {
        Objects.requireNonNull(tokenEnvelope);
        Objects.requireNonNull(receipt);
        Objects.requireNonNull(dpopNonce);
    }

    @Override
    public String toString() { return "EscrowedPasswordDelivery[redacted]"; }
}
