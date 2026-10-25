package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.security.RequestKeyThumbprint;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * The parts of a stored ACTIVE session that decide whether it may be extended.
 * {@code version} is the stored {@code sessionVersion}, used for compare-and-set.
 */
public record LiveSession(RequestKeyThumbprint requestKey, UUID generation,
                          SessionDeadlines deadlines, Instant customerStatusValidUntil,
                          long version) {
    public LiveSession {
        Objects.requireNonNull(requestKey, "requestKey");
        Objects.requireNonNull(generation, "generation");
        Objects.requireNonNull(deadlines, "deadlines");
        Objects.requireNonNull(customerStatusValidUntil, "customerStatusValidUntil");
    }

    boolean usableAt(Instant now) {
        return deadlines.activeAt(now) && now.isBefore(customerStatusValidUntil);
    }
}
