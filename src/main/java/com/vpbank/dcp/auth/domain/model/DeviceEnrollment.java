package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.MfaFactor;
import com.vpbank.dcp.auth.domain.exception.EnrollmentStateException;
import java.time.Instant;
import java.util.Objects;
import lombok.Builder;

/**
 * One trust transaction of an installation (phase 4). Two paths share the aggregate: the primary
 * enrollment of slice 5 (KEY_EXCHANGE → MFA_REQUIRED → COMPLETED, the device passes FACE itself) and
 * the approval of slice 6 (WAITING_APPROVAL → WAITING_AUTHORIZATION → COMPLETED, the current primary
 * device passes FACE + OTP and hands the new device a one-time authorization token). FAILED and EXPIRED
 * are terminal for both.
 *
 * <p>{@code deviceId} is the requesting installation; the row stores only its HMAC lookup, so the
 * caller supplies it when the aggregate is rebuilt. {@code targetDeviceId} is the device row that will
 * be trusted; {@code actorDeviceId} is the primary device that approved (approval path only). The
 * authorization token itself is never kept: only its SHA-256 digest, its expiry and the claim count.
 */
@Builder(toBuilder = true)
public record DeviceEnrollment(EnrollmentId id, CustomerId customerId, Channel channel, DeviceId deviceId,
                               EnrollmentPurpose purpose, EnrollmentState state, TrustedDeviceId targetDeviceId,
                               TrustedDeviceId actorDeviceId, String mfaTransactionId, String mfaMethod,
                               int verifyAttempts, String authorizationTokenDigest, Instant authorizationExpiresAt,
                               int authorizationAttempts, Instant authorizationConsumedAt, Instant expiresAt,
                               long version) {
    public DeviceEnrollment {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(purpose, "purpose");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (verifyAttempts < 0 || authorizationAttempts < 0) {
            throw new IllegalArgumentException("Attempt counts cannot be negative");
        }
        if (state == EnrollmentState.MFA_REQUIRED && mfaTransactionId == null) {
            throw new IllegalArgumentException("MFA_REQUIRED needs the MFA transaction ID");
        }
        if (state == EnrollmentState.WAITING_AUTHORIZATION
                && (authorizationTokenDigest == null || authorizationExpiresAt == null || actorDeviceId == null)) {
            throw new IllegalArgumentException("WAITING_AUTHORIZATION needs the approving device, the token digest and its expiry");
        }
    }

    /** Slice 5: the device itself will prove its key and pass FACE. */
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
                .authorizationAttempts(0)
                .expiresAt(expiresAt)
                .version(0)
                .build();
    }

    /** Slice 6: the request waits for the primary device; {@code targetDeviceId} is the PENDING or known live row. */
    public static DeviceEnrollment requestApproval(EnrollmentId id, CustomerId customerId, Channel channel, DeviceId deviceId,
                                                   TrustedDeviceId targetDeviceId, Instant expiresAt) {
        Objects.requireNonNull(targetDeviceId, "targetDeviceId");
        return DeviceEnrollment.builder()
                .id(id)
                .customerId(customerId)
                .channel(channel)
                .deviceId(deviceId)
                .purpose(EnrollmentPurpose.TRUST_DEVICE_APPROVAL)
                .state(EnrollmentState.WAITING_APPROVAL)
                .targetDeviceId(targetDeviceId)
                .verifyAttempts(0)
                .authorizationAttempts(0)
                .expiresAt(expiresAt)
                .version(0)
                .build();
    }

    public boolean isOpen(Instant now) {
        return state.open() && now.isBefore(expiresAt);
    }

    public boolean isApproval() {
        return purpose == EnrollmentPurpose.TRUST_DEVICE_APPROVAL;
    }

    // ---- slice 5 path ----

    public DeviceEnrollment countAttempt() {
        requireState(EnrollmentState.KEY_EXCHANGE);
        return toBuilder().verifyAttempts(verifyAttempts + 1).build();
    }

    public boolean attemptsExhausted(EnrollmentPolicy policy) {
        return verifyAttempts >= policy.maxVerifyAttempts();
    }

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
        return toBuilder()
                .state(EnrollmentState.COMPLETED)
                .mfaMethod(MfaFactor.FACE.name())
                .build();
    }

    // ---- slice 6 path ----

    /** The primary device picked this request and an MFA transaction (FACE + OTP) was opened for it. */
    public DeviceEnrollment approveBy(TrustedDeviceId approvingDeviceId, String mfaTransactionId) {
        requireState(EnrollmentState.WAITING_APPROVAL);
        Objects.requireNonNull(approvingDeviceId, "approvingDeviceId");
        Objects.requireNonNull(mfaTransactionId, "mfaTransactionId");
        if (this.mfaTransactionId != null) {
            throw new EnrollmentStateException("Enrollment already has an approval in progress");
        }
        return toBuilder()
                .actorDeviceId(approvingDeviceId)
                .mfaTransactionId(mfaTransactionId)
                .build();
    }

    public boolean hasApprovalInProgress() {
        return state == EnrollmentState.WAITING_APPROVAL && mfaTransactionId != null;
    }

    /** The approver's MFA passed: the one-time token is issued; only its digest and deadline are kept. */
    public DeviceEnrollment authorize(String tokenDigest, Instant tokenExpiresAt, String confirmedMfaMethod) {
        requireState(EnrollmentState.WAITING_APPROVAL);
        if (!hasApprovalInProgress()) {
            throw new EnrollmentStateException("Enrollment was not approved yet");
        }
        Objects.requireNonNull(tokenDigest, "tokenDigest");
        Objects.requireNonNull(tokenExpiresAt, "tokenExpiresAt");
        Objects.requireNonNull(confirmedMfaMethod, "confirmedMfaMethod");
        return toBuilder()
                .state(EnrollmentState.WAITING_AUTHORIZATION)
                .authorizationTokenDigest(tokenDigest)
                .authorizationExpiresAt(tokenExpiresAt)
                .mfaMethod(confirmedMfaMethod)
                .build();
    }

    public boolean authorizationExpired(Instant now) {
        return authorizationExpiresAt != null && !now.isBefore(authorizationExpiresAt);
    }

    public DeviceEnrollment countClaimAttempt() {
        requireState(EnrollmentState.WAITING_AUTHORIZATION);
        return toBuilder().authorizationAttempts(authorizationAttempts + 1).build();
    }

    public boolean claimAttemptsExhausted(EnrollmentPolicy policy) {
        return authorizationAttempts >= policy.maxClaimAttempts();
    }

    /** The new device presented the right token in time: the enrollment is complete. */
    public DeviceEnrollment consumeAuthorization(Instant now) {
        requireState(EnrollmentState.WAITING_AUTHORIZATION);
        if (authorizationExpired(now)) {
            throw new EnrollmentStateException("Authorization token expired");
        }
        return toBuilder()
                .state(EnrollmentState.COMPLETED)
                .authorizationConsumedAt(now)
                .build();
    }

    // ---- terminal states ----

    public DeviceEnrollment fail() {
        requireOpen();
        return toBuilder().state(EnrollmentState.FAILED).build();
    }

    public DeviceEnrollment expire() {
        requireOpen();
        return toBuilder().state(EnrollmentState.EXPIRED).build();
    }

    public DeviceEnrollment withVersion(long storedVersion) {
        return toBuilder().version(storedVersion).build();
    }

    private void requireOpen() {
        if (!state.open()) {
            throw new EnrollmentStateException("Enrollment is " + state);
        }
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
