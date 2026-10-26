package com.vpbank.dcp.auth.domain.model;

import java.time.Duration;
import java.util.Objects;

/**
 * Enrollment limits. Slice 5: how many wrong challenge answers one enrollment may take. Slice 6
 * (approval by the primary device): how long a request waits, how long the QR token lives, how many
 * wrong claims it survives and how many devices may wait at once per customer and channel.
 */
public record EnrollmentPolicy(int maxVerifyAttempts, Duration pendingWindow, Duration approvalTokenLifetime,
                               int maxClaimAttempts, int maxPendingDevices) {
    public EnrollmentPolicy {
        Objects.requireNonNull(pendingWindow, "pendingWindow");
        Objects.requireNonNull(approvalTokenLifetime, "approvalTokenLifetime");
        if (maxVerifyAttempts < 1 || maxVerifyAttempts > 10) {
            throw new IllegalArgumentException("maxVerifyAttempts must be 1..10");
        }
        if (pendingWindow.isNegative() || pendingWindow.isZero()) {
            throw new IllegalArgumentException("pendingWindow must be positive");
        }
        if (approvalTokenLifetime.isNegative() || approvalTokenLifetime.isZero()
                || approvalTokenLifetime.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("approvalTokenLifetime must be positive and at most 5 minutes");
        }
        if (maxClaimAttempts < 1 || maxClaimAttempts > 10) {
            throw new IllegalArgumentException("maxClaimAttempts must be 1..10");
        }
        if (maxPendingDevices < 1 || maxPendingDevices > 10) {
            throw new IllegalArgumentException("maxPendingDevices must be 1..10");
        }
    }

    public static EnrollmentPolicy standard() {
        return new EnrollmentPolicy(3, Duration.ofMinutes(10), Duration.ofSeconds(180), 5, 3);
    }
}
