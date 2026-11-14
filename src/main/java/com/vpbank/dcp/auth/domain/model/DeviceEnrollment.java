package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.MfaFactor;
import com.vpbank.dcp.auth.domain.exception.EnrollmentStateException;
import java.time.Instant;
import lombok.Builder;
import lombok.NonNull;

/**
 * One trust transaction of an installation (phase 4). Two paths share the aggregate: the primary
 * enrollment of slice 5 (the device passes FACE itself; since slice 11 its steps run on an
 * {@link EnrollmentTransaction} in the cache and the row is written once, MFA_REQUIRED → COMPLETED, at the
 * trust commit) and the approval of slice 6 (WAITING_APPROVAL → WAITING_AUTHORIZATION → COMPLETED, the
 * current primary device passes FACE + OTP and hands the new device a one-time authorization token).
 * FAILED and EXPIRED are terminal for the approval.
 *
 * <p>{@code deviceId} is the requesting installation. Approval keeps its protected identifier and
 * candidate key on the enrollment. {@code targetDeviceId} pins the existing binding, if any.
 * {@code actorDeviceId} is the primary device that approved. The
 * authorization token itself is never kept: only its SHA-256 digest, its expiry and the claim count.
 */
@Builder(toBuilder = true)
public record DeviceEnrollment(@NonNull EnrollmentId id,
                               @NonNull CustomerId customerId,
                               @NonNull Channel channel,
                               @NonNull DeviceId deviceId,
                               @NonNull EnrollmentPurpose purpose,
                               @NonNull EnrollmentState state,
                               DeviceKey candidateKey,
                               TrustedDeviceId targetDeviceId,
                               TrustedDeviceId actorDeviceId,
                               String mfaTransactionId,
                               String mfaMethod,
                               int verifyAttempts,
                               String authorizationTokenDigest,
                               Instant authorizationExpiresAt,
                               int authorizationAttempts,
                               Instant authorizationConsumedAt,
                               @NonNull Instant expiresAt,
                               long version) {
    public DeviceEnrollment {
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

    /** The installation that asked for trust. */
    public DeviceInstallation requester() {
        return new DeviceInstallation(customerId, channel, deviceId);
    }

    /** Waits for approval with the key fixed for this enrollment. */
    public static DeviceEnrollment requestApproval(@NonNull ApprovalRequestStart start) {
        DeviceInstallation requester = start.requester();
        return DeviceEnrollment.builder()
                .id(start.enrollmentId())
                .customerId(requester.customerId())
                .channel(requester.channel())
                .deviceId(requester.deviceId())
                .purpose(EnrollmentPurpose.TRUST_DEVICE_APPROVAL)
                .state(EnrollmentState.WAITING_APPROVAL)
                .candidateKey(start.candidateKey())
                .targetDeviceId(start.targetDeviceId())
                .verifyAttempts(0)
                .authorizationAttempts(0)
                .expiresAt(start.expiresAt())
                .version(0)
                .build();
    }

    /**
     * Slice 11: the primary enrollment that passed its key proof in the cache, as the row the trust commit
     * writes for the first time. It carries the attempts and the MFA transaction it had there, and the deadline
     * of its cache transaction.
     */
    public static DeviceEnrollment fromTransaction(@NonNull EnrollmentTransaction transaction,
                                                   @NonNull Instant expiresAt) {
        if (transaction.state() != EnrollmentState.MFA_REQUIRED) {
            throw new EnrollmentStateException("Only a transaction past its key proof becomes an enrollment row");
        }
        return DeviceEnrollment.builder()
                .id(transaction.id())
                .customerId(transaction.customerId())
                .channel(transaction.channel())
                .deviceId(transaction.deviceId())
                .purpose(EnrollmentPurpose.TRUST_DEVICE)
                .state(EnrollmentState.MFA_REQUIRED)
                .targetDeviceId(transaction.targetDeviceId())
                .mfaTransactionId(transaction.mfaTransactionId())
                .verifyAttempts(transaction.verifyAttempts())
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

    // ---- slice 5 path: the row is written at the trust commit (slice 11) ----

    public DeviceEnrollment complete() {
        requireState(EnrollmentState.MFA_REQUIRED);
        return toBuilder()
                .state(EnrollmentState.COMPLETED)
                .mfaMethod(MfaFactor.FACE.name())
                .build();
    }

    // ---- slice 6 path ----

    /** The primary device picked this request and an MFA transaction (FACE + OTP) was opened for it. */
    public DeviceEnrollment approveBy(@NonNull TrustedDeviceId approvingDeviceId, @NonNull String mfaTransactionId) {
        requireState(EnrollmentState.WAITING_APPROVAL);
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

    /** This device is the one that approved the request; only it may go on to collect the token. */
    public boolean wasApprovedBy(@NonNull TrustedDeviceId deviceId) {
        return deviceId.equals(actorDeviceId);
    }

    /** The approver passed MFA and a token is out; the request waits for the new device to claim it. */
    public boolean isAuthorized() {
        return state == EnrollmentState.WAITING_AUTHORIZATION;
    }

    /** The approver's MFA passed: the one-time token is issued; only its digest and deadline are kept. */
    public DeviceEnrollment authorize(@NonNull String tokenDigest,
                                      @NonNull Instant tokenExpiresAt,
                                      @NonNull String confirmedMfaMethod) {
        requireState(EnrollmentState.WAITING_APPROVAL);
        if (!hasApprovalInProgress()) {
            throw new EnrollmentStateException("Enrollment was not approved yet");
        }
        return toBuilder()
                .state(EnrollmentState.WAITING_AUTHORIZATION)
                .authorizationTokenDigest(tokenDigest)
                .authorizationExpiresAt(tokenExpiresAt)
                .mfaMethod(confirmedMfaMethod)
                .build();
    }

    /**
     * The approver asked for the token again: a new token replaces the one issued, which stops working. The
     * deadline and the claim attempts stay, so asking again buys the token no more time and no more tries.
     */
    public DeviceEnrollment reissueAuthorization(@NonNull String newTokenDigest, @NonNull Instant now) {
        requireState(EnrollmentState.WAITING_AUTHORIZATION);
        if (authorizationExpired(now)) {
            throw new EnrollmentStateException("Authorization token expired");
        }
        return toBuilder().authorizationTokenDigest(newTokenDigest).build();
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
