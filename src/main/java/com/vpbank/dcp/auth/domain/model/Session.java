package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.exception.SessionStateException;
import lombok.Builder;
import lombok.NonNull;

import java.time.Duration;
import java.time.Instant;

/**
 * One login session. An ACTIVE session's idle expiry slides with eligible activity up to the
 * fixed absolute expiry (DD 06 / flow 16). A NEED_TRUSTED_DEVICE session is restricted: one fixed
 * TTL, never extended (DD 20 §3); the trust flow it runs keeps its own record (slice 11:
 * {@link EnrollmentTransaction}). {@code sessionVersion} is the compare-and-set revision the store must
 * still see when it saves a change; each saved change increments it in the store.
 */
@Builder(toBuilder = true)
public record Session(@NonNull SessionId id,
                      @NonNull CustomerId customerId,
                      DeviceId deviceId,
                      @NonNull Channel channel,
                      @NonNull SessionStatus status,
                      @NonNull Instant createdAt,
                      @NonNull Instant idleExpiresAt,
                      @NonNull Instant absoluteExpiresAt,
                      long sessionVersion) {
    public Session {
        if (idleExpiresAt.isAfter(absoluteExpiresAt)) {
            throw new IllegalArgumentException("Idle expiry cannot pass the absolute expiry");
        }
    }

    /**
     * A fresh ACTIVE session: idle = start + idle, absolute = start + absolute, version 0.
     */
    public static Session start(@NonNull NewSession newSession, @NonNull SessionPolicy policy) {
        Instant startedAt = newSession.startedAt();
        return sessionOf(newSession)
                .status(SessionStatus.ACTIVE)
                .idleExpiresAt(startedAt.plus(policy.idle()))
                .absoluteExpiresAt(startedAt.plus(policy.absolute()))
                .build();
    }

    /**
     * A restricted session for a device that still needs trust: idle = absolute = start + TTL.
     */
    public static Session startRestricted(@NonNull NewSession newSession, @NonNull DevicePolicy policy) {
        // A restricted session has one fixed deadline: idle and absolute expiry are the same instant.
        Instant restrictedExpiresAt = newSession.startedAt().plus(policy.restrictedSessionTtl());
        return sessionOf(newSession)
                .status(SessionStatus.NEED_TRUSTED_DEVICE)
                .idleExpiresAt(restrictedExpiresAt)
                .absoluteExpiresAt(restrictedExpiresAt)
                .build();
    }

    /** The fields every new session starts with: who and where, when it was created, version 0. */
    private static SessionBuilder sessionOf(NewSession newSession) {
        return Session.builder()
                .id(newSession.id())
                .customerId(newSession.customerId())
                .deviceId(newSession.deviceId())
                .channel(newSession.channel())
                .createdAt(newSession.startedAt())
                .sessionVersion(0);
    }

    /**
     * Not ended and neither deadline has passed (restricted sessions are live too).
     */
    public boolean isLive(Instant now) {
        return status.live() && now.isBefore(idleExpiresAt) && now.isBefore(absoluteExpiresAt);
    }

    /**
     * Live and ACTIVE: may call business routes and be extended.
     */
    public boolean isFull(Instant now) {
        return isLive(now) && status.full();
    }

    /**
     * Flow 16: {@code idle = min(absolute, max(oldIdle, admittedAt + idle))}. The admission time,
     * not "now", drives the slide, so a retry never gains time. Rejects an admission time outside
     * the policy's skew around {@code now}.
     */
    public Session extend(Instant admittedAt, Instant now, SessionPolicy policy) {
        requireLive(now);
        if (!status.full()) {
            throw new SessionStateException("A " + status + " session is never extended");
        }
        Duration skew = Duration.between(admittedAt, now).abs();
        if (skew.compareTo(policy.maxAdmittedAtSkew()) > 0) {
            throw new IllegalArgumentException("Admission time is outside the accepted skew");
        }
        // The idle window slides from the admission time, never shrinks and never passes the absolute expiry.
        Instant slidIdleExpiresAt = admittedAt.plus(policy.idle());
        Instant newIdleExpiresAt = min(absoluteExpiresAt, max(idleExpiresAt, slidIdleExpiresAt));
        return toBuilder().idleExpiresAt(newIdleExpiresAt).build();
    }

    public Session end(Instant now) {
        if (!status.live()) {
            throw new SessionStateException("Session is already " + status);
        }
        return toBuilder().status(SessionStatus.ENDED).build();
    }

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
