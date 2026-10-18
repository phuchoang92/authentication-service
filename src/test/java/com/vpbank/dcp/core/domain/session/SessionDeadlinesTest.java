package com.vpbank.dcp.core.domain.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class SessionDeadlinesTest {

    private final Instant createdAt = Instant.parse("2026-10-11T03:00:00Z");

    @Test
    void eligibleAdmissionSlidesIdleButNeverAbsolute() {
        var initial = SessionDeadlines.createdAt(createdAt);
        var touched = initial.afterEligibleAdmission(createdAt.plusSeconds(60));

        assertEquals(createdAt.plusSeconds(960), touched.idleExpiresAt());
        assertEquals(createdAt.plusSeconds(1200), touched.absoluteExpiresAt());
    }

    @Test
    void nearAbsoluteDeadlineTouchIsCapped() {
        var deadlines = new SessionDeadlines(createdAt.plusSeconds(3550),
                createdAt.plusSeconds(3600));
        var touched = deadlines.afterEligibleAdmission(createdAt.plusSeconds(3540));

        assertEquals(deadlines.absoluteExpiresAt(), touched.idleExpiresAt());
        assertFalse(touched.activeAt(deadlines.absoluteExpiresAt()));
    }

    @Test
    void exactIdleExpiryCannotBeRevived() {
        var deadlines = SessionDeadlines.createdAt(createdAt);

        assertTrue(deadlines.activeAt(deadlines.idleExpiresAt().minusNanos(1)));
        assertThrows(InvalidSessionStateException.class,
                () -> deadlines.afterEligibleAdmission(deadlines.idleExpiresAt()));
    }
}
