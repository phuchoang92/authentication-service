package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.exception.SessionStateException;
import lombok.Builder;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * One login session. An ACTIVE session's idle expiry slides with eligible activity up to the
 * fixed absolute expiry (DD 06 / flow 16). A NEED_TRUSTED_DEVICE session is restricted: one fixed
 * TTL, never extended (DD 20 §3); it carries the enrollment context of the trust flow (null until
 * init). {@code sessionVersion} is the compare-and-set revision the store must still see when it
 * saves a change; each saved change increments it in the store.
 */
@Builder(toBuilder = true)
public record Session(SessionId id, CustomerId customerId, DeviceId deviceId, Channel channel,
                      SessionStatus status, Instant createdAt, Instant idleExpiresAt,
                      Instant absoluteExpiresAt, long sessionVersion, EnrollmentContext enrollment) {
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

    /**
     * A fresh ACTIVE session: idle = now + idle, absolute = now + absolute, version 0.
     */
    public static Session start(SessionId id, CustomerId customerId, DeviceId deviceId, Channel channel,
                                Instant now, SessionPolicy policy) {
        return Session.builder()
                .id(id)
                .customerId(customerId)
                .deviceId(deviceId)
                .channel(channel)
                .status(SessionStatus.ACTIVE)
                .createdAt(now)
                .idleExpiresAt(now.plus(policy.idle()))
                .absoluteExpiresAt(now.plus(policy.absolute()))
                .sessionVersion(0)
                .build();
    }

    /**
     * A restricted session for a device that still needs trust: idle = absolute = now + TTL.
     */
    public static Session startRestricted(SessionId id, CustomerId customerId, DeviceId deviceId, Channel channel,
                                          Instant now, DevicePolicy policy) {
        // A restricted session has one fixed deadline: idle and absolute expiry are the same instant.
        Instant restrictedExpiresAt = now.plus(policy.restrictedSessionTtl());
        return Session.builder()
                .id(id)
                .customerId(customerId)
                .deviceId(deviceId)
                .channel(channel)
                .status(SessionStatus.NEED_TRUSTED_DEVICE)
                .createdAt(now)
                .idleExpiresAt(restrictedExpiresAt)
                .absoluteExpiresAt(restrictedExpiresAt)
                .sessionVersion(0)
                .build();
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

    /**
     * Init attached the enrollment: its ID, the device key and Ksrv, the challenge digest. Restricted sessions only.
     */
    public Session withEnrollment(EnrollmentContext context) {
        if (status != SessionStatus.NEED_TRUSTED_DEVICE) {
            throw new SessionStateException("Only a restricted session carries an enrollment");
        }
        Objects.requireNonNull(context, "context");
        return toBuilder().enrollment(context).build();
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
