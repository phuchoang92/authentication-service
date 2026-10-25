package com.vpbank.dcp.core.session;

import java.util.Objects;

/**
 * Exact candidate and encrypted delivery, never a plaintext token or session authority.
 */
public record PreparedSession(SessionActivationSnapshot snapshot,
                              SessionCandidate candidate,
                              SessionDelivery delivery,
                              SessionDeadlines deadlines) {
    public PreparedSession {
        Objects.requireNonNull(snapshot);
        Objects.requireNonNull(candidate);
        Objects.requireNonNull(delivery);
        Objects.requireNonNull(deadlines);
    }

    @Override
    public String toString() {
        return "PreparedSession[redacted]";
    }
}
