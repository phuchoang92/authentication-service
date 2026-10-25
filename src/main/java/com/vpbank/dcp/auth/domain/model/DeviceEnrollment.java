package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.exception.EnrollmentStateException;
import java.time.Instant;
import java.util.Objects;
import lombok.Builder;

/**
 * One attempt to make an installation the customer's trusted primary device (DD 20 §4):
 * KEY_EXCHANGE (init handed out a challenge) → MFA_REQUIRED (the device proved its key, an MFA
 * transaction exists) → COMPLETED (FACE passed, trust committed), or FAILED / EXPIRED.
 * {@code verifyAttempts} counts challenge answers; {@code version} is the compare-and-set revision.
 */
@Builder(toBuilder = true)
public record DeviceEnrollment(EnrollmentId id, CustomerId customerId, Channel channel, DeviceId deviceId,
                               EnrollmentPurpose purpose, EnrollmentState state, TrustedDeviceId targetDeviceId,
                               String mfaTransactionId, int verifyAttempts, Instant expiresAt, long version) {
    public DeviceEnrollment {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(purpose, "purpose");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (verifyAttempts < 0) {
            throw new IllegalArgumentException("Verify attempts cannot be negative");
        }
        if (state == EnrollmentState.MFA_REQUIRED && mfaTransactionId == null) {
            throw new IllegalArgumentException("MFA_REQUIRED needs the MFA transaction ID");
        }
    }

    /** Started by init: the challenge is out, nothing proven yet. */
    public static DeviceEnrollment start(EnrollmentId id, CustomerId customerId, Channel channel, DeviceId deviceId,
                                         TrustedDeviceId targetDeviceId, Instant expiresAt) {
        return DeviceEnrollment.builder()
                .id(id)
                .customerId(customerId)
                .channel(channel)
                .deviceId(deviceId)
                .purpose(EnrollmentPurpose.TRUST_DEVICE)
                .state(EnrollmentState.KEY_EXCHANGE)
                .targetDeviceId(targetDeviceId)
                .verifyAttempts(0)
                .expiresAt(expiresAt)
                .version(0)
                .build();
    }

    public boolean isOpen(Instant now) {
        return state.open() && now.isBefore(expiresAt);
    }

    /** One more challenge answer, counted before it is checked. */
    public DeviceEnrollment countAttempt() {
        requireState(EnrollmentState.KEY_EXCHANGE);
        return toBuilder().verifyAttempts(verifyAttempts + 1).build();
    }

    public boolean attemptsExhausted(EnrollmentPolicy policy) {
        return verifyAttempts >= policy.maxVerifyAttempts();
    }

    /** The device proved its key and MFA opened a transaction. */
    public DeviceEnrollment markMfaRequired(String mfaTransactionId) {
        requireState(EnrollmentState.KEY_EXCHANGE);
        Objects.requireNonNull(mfaTransactionId, "mfaTransactionId");
        return toBuilder()
                .state(EnrollmentState.MFA_REQUIRED)
                .mfaTransactionId(mfaTransactionId)
                .build();
    }

    public DeviceEnrollment complete() {
        requireState(EnrollmentState.MFA_REQUIRED);
        return toBuilder().state(EnrollmentState.COMPLETED).build();
    }

    public DeviceEnrollment fail() {
        requireState(EnrollmentState.KEY_EXCHANGE, EnrollmentState.MFA_REQUIRED);
        return toBuilder().state(EnrollmentState.FAILED).build();
    }

    public DeviceEnrollment expire() {
        requireState(EnrollmentState.KEY_EXCHANGE, EnrollmentState.MFA_REQUIRED);
        return toBuilder().state(EnrollmentState.EXPIRED).build();
    }

    public DeviceEnrollment withVersion(long storedVersion) {
        return toBuilder().version(storedVersion).build();
    }

    private void requireState(EnrollmentState... allowed) {
        for (EnrollmentState candidate : allowed) {
            if (candidate == state) {
                return;
            }
        }
        throw new EnrollmentStateException("Enrollment is " + state);
    }
}
