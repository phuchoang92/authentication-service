package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.exception.EnrollmentStateException;
import java.util.Objects;
import lombok.Builder;

/**
 * A primary enrollment between init and confirm (slice 11), the payload of its cache transaction: whose it is
 * (customer, channel, device and the restricted session that started it), the device key and platform to
 * trust, the server key pair of this transaction (Ksrv; its private part lives only here, DD 20 §4), the digest
 * of the challenge sent, the attempts made and, after the key proof, the MFA transaction. KEY_EXCHANGE after
 * init, MFA_REQUIRED after verify; failure, expiry and the trust commit end it by removing the transaction, so
 * it has no terminal state. The deadline and the compare-and-set version belong to the transaction envelope.
 */
@Builder(toBuilder = true)
public record EnrollmentTransaction(EnrollmentId id, CustomerId customerId, Channel channel, DeviceId deviceId,
                                    SessionId sessionId, EnrollmentState state, TrustedDeviceId targetDeviceId,
                                    String devicePublicJwk, DevicePlatform platform, String serverPublicJwk,
                                    String serverPrivateJwk, String challengeDigest, int verifyAttempts,
                                    String mfaTransactionId) {
    public EnrollmentTransaction {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(devicePublicJwk, "devicePublicJwk");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(serverPublicJwk, "serverPublicJwk");
        Objects.requireNonNull(serverPrivateJwk, "serverPrivateJwk");
        Objects.requireNonNull(challengeDigest, "challengeDigest");
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

    /**
     * Init: the device is challenged to prove its key. {@code targetDeviceId} is the device row a known device
     * already has (null for a new device).
     */
    public static EnrollmentTransaction keyExchange(EnrollmentId id, AdmittedSession owner, TrustedDeviceId targetDeviceId,
                                                    String devicePublicJwk, DevicePlatform platform,
                                                    String serverPublicJwk, String serverPrivateJwk,
                                                    String challengeDigest) {
        Objects.requireNonNull(owner, "owner");
        return EnrollmentTransaction.builder()
                .id(id)
                .customerId(owner.customerId())
                .channel(owner.channel())
                .deviceId(owner.deviceId())
                .sessionId(owner.sessionId())
                .state(EnrollmentState.KEY_EXCHANGE)
                .targetDeviceId(targetDeviceId)
                .devicePublicJwk(devicePublicJwk)
                .platform(platform)
                .serverPublicJwk(serverPublicJwk)
                .serverPrivateJwk(serverPrivateJwk)
                .challengeDigest(challengeDigest)
                .verifyAttempts(0)
                .build();
    }

    /** Started by this admitted session: same session, customer, channel and device. */
    public boolean belongsTo(AdmittedSession caller) {
        return sessionId.equals(caller.sessionId())
                && customerId.equals(caller.customerId())
                && channel == caller.channel()
                && deviceId.equals(caller.deviceId());
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
    public EnrollmentTransaction markMfaRequired(String mfaTransactionId) {
        requireState(EnrollmentState.KEY_EXCHANGE);
        Objects.requireNonNull(mfaTransactionId, "mfaTransactionId");
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
