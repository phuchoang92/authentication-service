package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.exception.SessionStateException;
import lombok.Builder;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * One login session. Idle expiry slides with eligible activity up to the fixed absolute
 * expiry (DD 06 / flow 16). {@code sessionVersion} is the compare-and-set revision the store
 * must still see when it saves a change; each saved change increments it in the store.
 */
@Builder(toBuilder = true)
public record Session(SessionId id, CustomerId customerId, DeviceId deviceId, Channel channel,
                      SessionStatus status, Instant createdAt, Instant idleExpiresAt,
                      Instant absoluteExpiresAt, long sessionVersion) {
    public Session {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(idleExpiresAt, "idleExpiresAt");
        Objects.requireNonNull(absoluteExpiresAt, "absoluteExpiresAt");
        if (idleExpiresAt.isAfter(absoluteExpiresAt)) {
            throw new IllegalArgumentException("Idle expiry cannot pass the absolute expiry");
        }
    }

    /** A fresh ACTIVE session: idle = now + idle, absolute = now + absolute, version 0. */
    public static Session start(SessionId id, CustomerId customerId, DeviceId deviceId, Channel channel,
                                Instant now, SessionPolicy policy) {
        return Session.builder().id(id).customerId(customerId).deviceId(deviceId).channel(channel)
                .status(SessionStatus.ACTIVE).createdAt(now)
                .idleExpiresAt(now.plus(policy.idle())).absoluteExpiresAt(now.plus(policy.absolute()))
                .sessionVersion(0).build();
    }

    /** ACTIVE and neither deadline has passed. */
    public boolean isLive(Instant now) {
        return status == SessionStatus.ACTIVE && now.isBefore(idleExpiresAt) && now.isBefore(absoluteExpiresAt);
    }

    /**
     * Flow 16: {@code idle = min(absolute, max(oldIdle, admittedAt + idle))}. The admission time,
     * not "now", drives the slide, so a retry never gains time. Rejects an admission time outside
     * the policy's skew around {@code now}.
     */
    public Session extend(Instant admittedAt, Instant now, SessionPolicy policy) {
        requireLive(now);
        Duration skew = Duration.between(admittedAt, now).abs();
        if (skew.compareTo(policy.maxAdmittedAtSkew()) > 0) {
            throw new IllegalArgumentException("Admission time is outside the accepted skew");
        }
        Instant slid = admittedAt.plus(policy.idle());
        Instant newIdle = min(absoluteExpiresAt, max(idleExpiresAt, slid));
        return toBuilder().idleExpiresAt(newIdle).build();
    }

    public Session end(Instant now) {
        if (status != SessionStatus.ACTIVE) {
            throw new SessionStateException("Session is already " + status);
        }
        return toBuilder().status(SessionStatus.ENDED).build();
    }

    /** The store saw this version; the next change builds on it. */
    public Session withSessionVersion(long storedVersion) {
        return toBuilder().sessionVersion(storedVersion).build();
    }

    private void requireLive(Instant now) {
        if (!isLive(now)) {
            throw new SessionStateException("Session is not live: status=" + status);
        }
    }

    private static Instant min(Instant a, Instant b) {
        return a.isBefore(b) ? a : b;
    }

    private static Instant max(Instant a, Instant b) {
        return a.isAfter(b) ? a : b;
    }
}
