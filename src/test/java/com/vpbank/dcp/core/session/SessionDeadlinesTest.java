package com.vpbank.dcp.core.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class SessionDeadlinesTest {

    private final Instant createdAt = Instant.parse("2026-10-11T03:00:00Z");

    @Test
    void admissionSlidesIdleButNeverAbsolute() {
        var initial = SessionDeadlines.createdAt(createdAt);
        var slid = initial.slideFor(createdAt.plusSeconds(60));

        assertEquals(createdAt.plusSeconds(960), slid.idleExpiresAt());
        assertEquals(createdAt.plusSeconds(1200), slid.absoluteExpiresAt());
    }

    @Test
    void slideIsCappedAtAbsolute() {
        var initial = SessionDeadlines.createdAt(createdAt);
        var slid = initial.slideFor(createdAt.plusSeconds(600));

        assertEquals(initial.absoluteExpiresAt(), slid.idleExpiresAt());
        assertFalse(slid.activeAt(initial.absoluteExpiresAt()));
    }

    @Test
    void olderAdmissionNeverShortensIdle() {
        var later = SessionDeadlines.createdAt(createdAt).slideFor(createdAt.plusSeconds(120));

        assertEquals(later, later.slideFor(createdAt.plusSeconds(60)));
    }

    @Test
    void retryOfSameAdmissionIsStable() {
        Instant admittedAt = createdAt.plusSeconds(60);
        var once = SessionDeadlines.createdAt(createdAt).slideFor(admittedAt);

        assertEquals(once, once.slideFor(admittedAt));
    }

    @Test
    void slideKeepsOnlyMilliseconds() {
        var slid = SessionDeadlines.createdAt(createdAt)
                .slideFor(createdAt.plusSeconds(60).plusNanos(123_456_789));

        assertEquals(createdAt.plusSeconds(960).plusMillis(123), slid.idleExpiresAt());
    }

    @Test
    void exactIdleExpiryIsNotActive() {
        var deadlines = SessionDeadlines.createdAt(createdAt);

        assertTrue(deadlines.activeAt(deadlines.idleExpiresAt().minusNanos(1)));
        assertFalse(deadlines.activeAt(deadlines.idleExpiresAt()));
    }
}
