package com.vpbank.dcp.core.session;

import com.vpbank.dcp.core.session.ExtendSessionResult.Extended;
import com.vpbank.dcp.core.session.ExtendSessionResult.NotExtended;
import com.vpbank.dcp.core.session.ExtendSessionResult.Reason;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Slides the idle deadline of an ACTIVE session after the Mobile BFF admitted one App request.
 *
 * <p>Only the session hash is checked: there are no Valkey guards yet, so a Customer block or
 * device revoke is not seen here until that gate is built (flow 16, doc 18). Integration only.
 */
public final class ExtendSessionService {
    static final int MAX_ATTEMPTS = 3;

    private final SessionActivityStore store;
    private final Clock clock;
    private final Set<String> activityRoutes;
    private final Duration maxAdmissionAge;
    private final Duration maxClockSkew;

    public ExtendSessionService(SessionActivityStore store, Clock clock, Set<String> activityRoutes,
                                Duration maxAdmissionAge, Duration maxClockSkew) {
        this.store = Objects.requireNonNull(store);
        this.clock = Objects.requireNonNull(clock);
        this.activityRoutes = Set.copyOf(activityRoutes);
        this.maxAdmissionAge = Objects.requireNonNull(maxAdmissionAge);
        this.maxClockSkew = Objects.requireNonNull(maxClockSkew);
        if (maxAdmissionAge.isNegative() || maxAdmissionAge.isZero() || maxClockSkew.isNegative()) {
            throw new IllegalArgumentException("admission window must be positive");
        }
    }

    public ExtendSessionResult extend(ExtendSessionCommand command) {
        Objects.requireNonNull(command, "command");
        if (!countsAsActivity(command, clock.instant())) {
            return new NotExtended(Reason.INVALID_REQUEST);
        }
        try {
            // A lost race re-reads and recomputes from the same admittedAt, never from now.
            for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
                Optional<LiveSession> found = store.find(command.sessionId());
                if (found.isEmpty() || !found.get().usableAt(clock.instant())) {
                    return new NotExtended(Reason.GONE);
                }
                LiveSession live = found.get();
                Optional<UUID> generation = store.currentGeneration();
                if (generation.isEmpty()) {
                    return new NotExtended(Reason.UNAVAILABLE);
                }
                if (!live.generation().equals(generation.get())
                        || !live.requestKey().equals(command.requestKey())) {
                    return new NotExtended(Reason.CONFLICT);
                }
                SessionDeadlines next = live.deadlines().slideFor(command.admittedAt());
                if (next.equals(live.deadlines())
                        || store.slideIdle(command.sessionId(), live.version(), next.idleExpiresAt())) {
                    return new Extended(next);
                }
            }
            return new NotExtended(Reason.CONFLICT);
        } catch (SessionActivityUnavailableException failure) {
            return new NotExtended(Reason.UNAVAILABLE);
        }
    }

    private boolean countsAsActivity(ExtendSessionCommand command, Instant now) {
        Instant admittedAt = command.admittedAt();
        return activityRoutes.contains(command.routeId())
                && !admittedAt.isAfter(now.plus(maxClockSkew))
                && !admittedAt.isBefore(now.minus(maxAdmissionAge));
    }
}
