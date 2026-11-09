package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.exception.EnrollmentStateException;
import lombok.Builder;
import lombok.NonNull;

/**
 * A primary enrollment between init and confirm (slice 11), the payload of its cache transaction: whose it is
 * (customer, channel, device and the restricted session that started it), the device key and platform to
 * trust, the server key pair of this transaction (Ksrv; its private part lives only here, DD 20 §4), the digest
 * of the challenge sent, the attempts made and, after the key proof, the MFA transaction. KEY_EXCHANGE after
 * init, MFA_REQUIRED after verify; failure, expiry and the trust commit end it by removing the transaction, so
 * it has no terminal state. The deadline belongs to the transaction envelope. Every step moves the record
 * forward (one more attempt, the next state): the store tells two moments apart by this record alone.
 */
@Builder(toBuilder = true)
public record EnrollmentTransaction(@NonNull EnrollmentId id,
                                    @NonNull CustomerId customerId,
                                    @NonNull Channel channel,
                                    @NonNull DeviceId deviceId,
                                    @NonNull SessionId sessionId,
                                    @NonNull EnrollmentState state,
                                    TrustedDeviceId targetDeviceId,
                                    @NonNull String devicePublicJwk,
                                    @NonNull DevicePlatform platform,
                                    @NonNull String serverPublicJwk,
                                    @NonNull String serverPrivateJwk,
                                    @NonNull String challengeDigest,
                                    int verifyAttempts,
                                    String mfaTransactionId) {
    public EnrollmentTransaction {
        if (state != EnrollmentState.KEY_EXCHANGE && state != EnrollmentState.MFA_REQUIRED) {
            throw new IllegalArgumentException("An enrollment transaction is KEY_EXCHANGE or MFA_REQUIRED");
        }
        // The MFA transaction exists exactly from the key proof on.
        boolean hasMfaTransaction = mfaTransactionId != null;
        if (hasMfaTransaction != (state == EnrollmentState.MFA_REQUIRED)) {
            throw new IllegalArgumentException("MFA_REQUIRED, and only MFA_REQUIRED, carries the MFA transaction ID");
        }
        if (verifyAttempts < 0) {
            throw new IllegalArgumentException("Attempts cannot be negative");
        }
    }

    /** Init: the new device is challenged to prove its key; no attempt is made yet. */
    public static EnrollmentTransaction keyExchange(@NonNull KeyExchangeStart start) {
        AdmittedSession newDeviceSession = start.newDeviceSession();
        DeviceKey deviceKey = start.deviceKey();
        return EnrollmentTransaction.builder()
                .id(start.enrollmentId())
                .customerId(newDeviceSession.customerId())
                .channel(newDeviceSession.channel())
                .deviceId(newDeviceSession.deviceId())
                .sessionId(newDeviceSession.sessionId())
                .state(EnrollmentState.KEY_EXCHANGE)
                .targetDeviceId(start.targetDeviceId())
                .devicePublicJwk(deviceKey.publicJwk())
                .platform(deviceKey.platform())
                .serverPublicJwk(start.serverPublicJwk())
                .serverPrivateJwk(start.serverPrivateJwk())
                .challengeDigest(start.challengeDigest())
                .verifyAttempts(0)
                .build();
    }

    /** Started by this restricted session: same session, customer, channel and device. */
    public boolean belongsTo(AdmittedSession newDeviceSession) {
        return sessionId.equals(newDeviceSession.sessionId())
                && customerId.equals(newDeviceSession.customerId())
                && channel == newDeviceSession.channel()
                && deviceId.equals(newDeviceSession.deviceId());
    }

    /** Counted before the answer is checked, so a lost race cannot grant a free try. */
    public EnrollmentTransaction countVerifyAttempt() {
        requireState(EnrollmentState.KEY_EXCHANGE);
        return toBuilder().verifyAttempts(verifyAttempts + 1).build();
    }

    public boolean attemptsExhausted(EnrollmentPolicy policy) {
        return verifyAttempts >= policy.maxVerifyAttempts();
    }

    /** The device proved its key; the MFA service now holds a FACE transaction for this enrollment. */
    public EnrollmentTransaction markMfaRequired(@NonNull String mfaTransactionId) {
        requireState(EnrollmentState.KEY_EXCHANGE);
        return toBuilder()
                .state(EnrollmentState.MFA_REQUIRED)
                .mfaTransactionId(mfaTransactionId)
                .build();
    }

    private void requireState(EnrollmentState expected) {
        if (state != expected) {
            throw new EnrollmentStateException("Enrollment transaction is " + state);
        }
    }

    @Override
    public String toString() {
        return "EnrollmentTransaction[id=" + id + ", state=" + state + ", verifyAttempts=" + verifyAttempts + ", redacted]";
    }
}
