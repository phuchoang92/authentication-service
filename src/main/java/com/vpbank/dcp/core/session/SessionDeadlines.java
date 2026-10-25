package com.vpbank.dcp.core.session;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

/**
 * Idle expiry slides after an admitted BFF request; absolute expiry never slides.
 */
public record SessionDeadlines(Instant idleExpiresAt, Instant absoluteExpiresAt) {

    public static final Duration IDLE_LIMIT = Duration.ofMinutes(15);
    public static final Duration ABSOLUTE_LIMIT = Duration.ofMinutes(20);

    public SessionDeadlines {
        Objects.requireNonNull(idleExpiresAt, "idleExpiresAt");
        Objects.requireNonNull(absoluteExpiresAt, "absoluteExpiresAt");
        if (idleExpiresAt.isAfter(absoluteExpiresAt)) {
            throw new IllegalArgumentException("Invalid banking session state");
        }
    }

    public static SessionDeadlines createdAt(Instant now) {
        Objects.requireNonNull(now, "now");
        return new SessionDeadlines(now.plus(IDLE_LIMIT), now.plus(ABSOLUTE_LIMIT));
    }

    public boolean activeAt(Instant now) {
        Objects.requireNonNull(now, "now");
        return now.isBefore(idleExpiresAt) && now.isBefore(absoluteExpiresAt);
    }

    /**
     * Idle becomes {@code min(absolute, max(idle, admittedAt + IDLE_LIMIT))}. Using the admission
     * time, not the call time, means a retry of the same admission never extends further.
     * Milliseconds only, because that is what Valkey stores.
     */
    public SessionDeadlines slideFor(Instant admittedAt) {
        Objects.requireNonNull(admittedAt, "admittedAt");
        Instant slid = admittedAt.plus(IDLE_LIMIT).truncatedTo(ChronoUnit.MILLIS);
        Instant idle = slid.isAfter(idleExpiresAt) ? slid : idleExpiresAt;
        return new SessionDeadlines(idle.isBefore(absoluteExpiresAt) ? idle : absoluteExpiresAt,
                absoluteExpiresAt);
    }
}
