package com.vpbank.dcp.auth.domain.model;

import lombok.Builder;

import java.time.Instant;
import java.util.Objects;

/**
 * The lockout part of an identity (phase 2 columns). Status and lockout time always change
 * together; the counter never goes below zero and resets only on a successful login.
 */
@Builder(toBuilder = true)
public record PasswordLockout(PasswordStatus status, int failedCount, Instant lockedUntil) {
    public PasswordLockout {
        Objects.requireNonNull(status, "status");
        if (failedCount < 0) {
            throw new IllegalArgumentException("Failed count cannot be negative");
        }
        if ((status == PasswordStatus.LOCKED) != (lockedUntil != null)) {
            throw new IllegalArgumentException("LOCKED and the lockout time are set together");
        }
    }

    public static PasswordLockout none() {
        return new PasswordLockout(PasswordStatus.ACTIVE, 0, null);
    }

    /** Permanently locked, or temporarily locked and the time has not passed yet. */
    public boolean isLocked(Instant now) {
        return status == PasswordStatus.PERMANENTLY_LOCKED
                || (status == PasswordStatus.LOCKED && now.isBefore(lockedUntil));
    }

    public boolean captchaRequired(LockoutPolicy policy) {
        return failedCount >= policy.captchaAfter();
    }

    /** One more consecutive failure: escalate per the policy. An expired temporary lock does not reset anything. */
    public PasswordLockout afterFailure(Instant now, LockoutPolicy policy) {
        int count = failedCount + 1;
        if (count >= policy.permanentAt()) {
            return new PasswordLockout(PasswordStatus.PERMANENTLY_LOCKED, count, null);
        }
        return policy.temporaryLockAt(count)
                .map(lock -> new PasswordLockout(PasswordStatus.LOCKED, count, now.plus(lock)))
                .orElseGet(() -> new PasswordLockout(PasswordStatus.ACTIVE, count, null));
    }

    /** A successful login, or the bank's unlock. */
    public PasswordLockout reset() {
        return none();
    }
}
