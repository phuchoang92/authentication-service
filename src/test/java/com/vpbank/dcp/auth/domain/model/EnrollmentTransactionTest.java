package com.vpbank.dcp.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.exception.EnrollmentStateException;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** The primary enrollment between init and confirm: KEY_EXCHANGE → MFA_REQUIRED, attempts, owner, redaction. */
class EnrollmentTransactionTest {
    private static final Instant FACE_DEADLINE = Instant.parse("2026-10-25T10:05:00Z");
    private static final AdmittedSession TABLET = new AdmittedSession(SessionId.random(), new CustomerId("90359"),
            Channel.MOBILE, new DeviceId("tablet-2"), SessionStatus.NEED_TRUSTED_DEVICE);

    private static final KeyExchangeStart TABLET_START = KeyExchangeStart.builder()
            .enrollmentId(EnrollmentId.random())
            .newDeviceSession(TABLET)
            .deviceKey(new DeviceKey("{dev}", DevicePlatform.IOS))
            .serverPublicJwk("{srv-pub}")
            .serverPrivateJwk("{srv-priv}")
            .challengeDigest("challenge-digest")
            .sealedChallenge("jwe.challenge")
            .build();

    private final EnrollmentTransaction started = EnrollmentTransaction.keyExchange(TABLET_START);

    @Test
    void initStartsInKeyExchangeOwnedByTheAdmittedSession() {
        assertThat(started.state()).isEqualTo(EnrollmentState.KEY_EXCHANGE);
        assertThat(started.verifyAttempts()).isZero();
        assertThat(started.mfaTransactionId()).isNull();
        assertThat(started.mfaExpiresAt()).isNull();
        assertThat(started.keyProven()).isFalse();
        assertThat(started.sealedChallenge()).isEqualTo("jwe.challenge"); // kept so a repeated init answers the same
        assertThat(started.customerId()).isEqualTo(TABLET.customerId());
        assertThat(started.deviceId()).isEqualTo(TABLET.deviceId());
        assertThat(started.sessionId()).isEqualTo(TABLET.sessionId());
        assertThat(started.belongsTo(TABLET)).isTrue();
    }

    @Test
    void anotherSessionOfTheSameDeviceOrAnotherDeviceIsNotTheOwner() {
        AdmittedSession laterLogin = new AdmittedSession(SessionId.random(), TABLET.customerId(), Channel.MOBILE,
                TABLET.deviceId(), SessionStatus.NEED_TRUSTED_DEVICE);
        AdmittedSession otherDevice = new AdmittedSession(TABLET.sessionId(), TABLET.customerId(), Channel.MOBILE,
                new DeviceId("phone-1"), SessionStatus.NEED_TRUSTED_DEVICE);
        AdmittedSession otherChannel = new AdmittedSession(TABLET.sessionId(), TABLET.customerId(), Channel.WEB,
                TABLET.deviceId(), SessionStatus.NEED_TRUSTED_DEVICE);

        assertThat(started.belongsTo(laterLogin)).isFalse();
        assertThat(started.belongsTo(otherDevice)).isFalse();
        assertThat(started.belongsTo(otherChannel)).isFalse();
    }

    @Test
    void attemptsAreCountedInKeyExchangeAndTheKeyProofOpensMfaRequired() {
        EnrollmentTransaction twoAttempts = started.countVerifyAttempt().countVerifyAttempt();
        assertThat(twoAttempts.verifyAttempts()).isEqualTo(2);
        assertThat(twoAttempts.attemptsExhausted(EnrollmentPolicy.standard())).isFalse();
        assertThat(twoAttempts.countVerifyAttempt().attemptsExhausted(EnrollmentPolicy.standard())).isTrue();

        EnrollmentTransaction mfaRequired = twoAttempts.markMfaRequired("mfa-1", FACE_DEADLINE);
        assertThat(mfaRequired.state()).isEqualTo(EnrollmentState.MFA_REQUIRED);
        assertThat(mfaRequired.keyProven()).isTrue();
        assertThat(mfaRequired.mfaTransactionId()).isEqualTo("mfa-1");
        assertThat(mfaRequired.mfaExpiresAt()).isEqualTo(FACE_DEADLINE); // kept so a repeated verify answers the same
        assertThat(mfaRequired.verifyAttempts()).isEqualTo(2);

        assertThatThrownBy(mfaRequired::countVerifyAttempt).isInstanceOf(EnrollmentStateException.class);
        assertThatThrownBy(() -> mfaRequired.markMfaRequired("mfa-2", FACE_DEADLINE))
                .isInstanceOf(EnrollmentStateException.class);
        assertThatThrownBy(() -> started.markMfaRequired(null, FACE_DEADLINE)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> started.markMfaRequired("mfa-1", null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void onlyTheTwoInFlightStatesExistAndTheMfaTransactionMatchesTheState() {
        assertThatThrownBy(() -> started.toBuilder().state(EnrollmentState.COMPLETED).build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> started.toBuilder().state(EnrollmentState.WAITING_APPROVAL).build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> started.toBuilder().state(EnrollmentState.MFA_REQUIRED).build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> started.toBuilder().mfaTransactionId("mfa-1").build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> started.toBuilder().mfaExpiresAt(FACE_DEADLINE).build())
                .isInstanceOf(IllegalArgumentException.class);
        // MFA_REQUIRED needs both the MFA transaction and its deadline.
        assertThatThrownBy(() -> started.toBuilder().state(EnrollmentState.MFA_REQUIRED).mfaTransactionId("mfa-1").build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> started.toBuilder().verifyAttempts(-1).build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> started.toBuilder().serverPrivateJwk(null).build())
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> started.toBuilder().sealedChallenge(null).build())
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void theServerKeyAndTheChallengeAreNeverPrinted() {
        assertThat(started.toString())
                .doesNotContain("srv-priv")
                .doesNotContain("challenge-digest")
                .doesNotContain("jwe.challenge")
                .doesNotContain("{dev}");
    }
}
