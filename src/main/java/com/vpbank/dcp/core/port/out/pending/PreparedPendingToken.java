package com.vpbank.dcp.core.port.out.pending;

import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.util.Objects;

/** Encrypted restricted token and its lookup; plaintext never crosses this port. */
public record PreparedPendingToken(SessionTokenLookup lookup, String tokenEnvelope, String receipt) {
    public PreparedPendingToken {
        Objects.requireNonNull(lookup);
        Objects.requireNonNull(tokenEnvelope);
        Objects.requireNonNull(receipt);
    }

    @Override
    public String toString() {
        return "PreparedPendingToken[redacted]";
    }
}
