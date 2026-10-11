package com.vpbank.dcp.core.domain.session;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Idle expiry can slide only after eligible Auth admission; absolute expiry never slides.
 */
public record SessionDeadlines(Instant idleExpiresAt, Instant absoluteExpiresAt) {

    public static final Duration IDLE_LIMIT = Duration.ofMinutes(15);
    public static final Duration ABSOLUTE_LIMIT = Duration.ofHours(1);

    public SessionDeadlines {
        Objects.requireNonNull(idleExpiresAt, "idleExpiresAt");
        Objects.requireNonNull(absoluteExpiresAt, "absoluteExpiresAt");
        if (idleExpiresAt.isAfter(absoluteExpiresAt)) {
            throw new InvalidSessionStateException();
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

    public SessionDeadlines afterEligibleAdmission(Instant now) {
        if (!activeAt(now)) {
            throw new InvalidSessionStateException();
        }
        Instant candidate = now.plus(IDLE_LIMIT);
        return new SessionDeadlines(candidate.isBefore(absoluteExpiresAt)
                ? candidate : absoluteExpiresAt, absoluteExpiresAt);
    }
}
