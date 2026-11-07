package com.vpbank.dcp.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.exception.EnrollmentStateException;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class DeviceEnrollmentTest {
    private static final Instant T0 = Instant.parse("2026-10-25T10:00:00Z");
    private static final DeviceInstallation WATCH =
            new DeviceInstallation(new CustomerId("90359"), Channel.MOBILE, new DeviceId("watch-3"));
    private static final AdmittedSession TABLET_SESSION = new AdmittedSession(SessionId.random(),
            new CustomerId("90359"), Channel.MOBILE, new DeviceId("tablet-2"),
            com.vpbank.dcp.auth.domain.enums.SessionStatus.NEED_TRUSTED_DEVICE);
    private static final KeyExchangeStart TABLET_START = KeyExchangeStart.builder()
            .enrollmentId(EnrollmentId.random())
            .newDeviceSession(TABLET_SESSION)
            .deviceKey(new DeviceKey("{dev}", DevicePlatform.IOS))
            .serverPublicJwk("{pub}")
            .serverPrivateJwk("{priv}")
            .challengeDigest("digest")
            .build();
    /** A primary enrollment's row as the trust commit first sees it: past its key proof in the cache (slice 11). */
    private final DeviceEnrollment primaryRow = DeviceEnrollment.fromTransaction(
            EnrollmentTransaction.keyExchange(TABLET_START).markMfaRequired("mfa-1"),
            T0.plus(Duration.ofMinutes(10)));

    @Test
    void thePrimaryRowGoesFromMfaRequiredToCompletedAtTheCommit() {
        assertThat(primaryRow.state()).isEqualTo(EnrollmentState.MFA_REQUIRED);
        assertThat(primaryRow.isOpen(T0)).isTrue();
        assertThat(primaryRow.isOpen(T0.plus(Duration.ofMinutes(10)))).isFalse();
        DeviceEnrollment done = primaryRow.complete();
        assertThat(done.state()).isEqualTo(EnrollmentState.COMPLETED);
        assertThat(done.mfaMethod()).isEqualTo("FACE");
        assertThat(done.isOpen(T0)).isFalse();
    }

    @Test
    void anApprovalWaitsThenHoldsTheTokenDigestThenCompletesOnTheClaim() {
        TrustedDeviceId target = TrustedDeviceId.random();
        TrustedDeviceId primary = TrustedDeviceId.random();
        DeviceEnrollment requested = DomainFixtures.approvalRequest(WATCH,
                target, T0.plus(Duration.ofMinutes(10)));
        assertThat(requested.state()).isEqualTo(EnrollmentState.WAITING_APPROVAL);
        assertThat(requested.isApproval()).isTrue();
        assertThat(requested.isOpen(T0)).isTrue();
        assertThat(requested.hasApprovalInProgress()).isFalse();
        assertThatThrownBy(() -> requested.authorize("digest", T0.plusSeconds(180), "FACE+OTP"))
                .isInstanceOf(EnrollmentStateException.class);

        DeviceEnrollment approved = requested.approveBy(primary, "mfa-9");
        assertThat(approved.state()).isEqualTo(EnrollmentState.WAITING_APPROVAL);
        assertThat(approved.actorDeviceId()).isEqualTo(primary);
        assertThat(approved.hasApprovalInProgress()).isTrue();
        assertThatThrownBy(() -> approved.approveBy(primary, "mfa-10")).isInstanceOf(EnrollmentStateException.class);

        DeviceEnrollment authorized = approved.authorize("digest", T0.plusSeconds(180), "FACE+OTP");
        assertThat(authorized.state()).isEqualTo(EnrollmentState.WAITING_AUTHORIZATION);
        assertThat(authorized.isOpen(T0)).isTrue();
        assertThat(authorized.authorizationExpired(T0.plusSeconds(179))).isFalse();
        assertThat(authorized.authorizationExpired(T0.plusSeconds(180))).isTrue();
        assertThat(authorized.mfaMethod()).isEqualTo("FACE+OTP");

        DeviceEnrollment counted = authorized.countClaimAttempt().countClaimAttempt();
        assertThat(counted.authorizationAttempts()).isEqualTo(2);
        assertThat(counted.claimAttemptsExhausted(EnrollmentPolicy.standard())).isFalse();
        assertThat(counted.countClaimAttempt().countClaimAttempt().countClaimAttempt()
                .claimAttemptsExhausted(EnrollmentPolicy.standard())).isTrue();

        assertThatThrownBy(() -> counted.consumeAuthorization(T0.plusSeconds(180))).isInstanceOf(EnrollmentStateException.class);
        DeviceEnrollment consumed = counted.consumeAuthorization(T0.plusSeconds(60));
        assertThat(consumed.state()).isEqualTo(EnrollmentState.COMPLETED);
        assertThat(consumed.authorizationConsumedAt()).isEqualTo(T0.plusSeconds(60));
        assertThatThrownBy(consumed::fail).isInstanceOf(EnrollmentStateException.class);
        assertThat(authorized.fail().state()).isEqualTo(EnrollmentState.FAILED);
        assertThat(requested.expire().state()).isEqualTo(EnrollmentState.EXPIRED);
    }

    @Test
    void stepsOutOfOrderAreProgrammingErrorsAndTerminalStatesStayTerminal() {
        DeviceEnrollment requested = DomainFixtures.approvalRequest(WATCH,
                TrustedDeviceId.random(), T0.plus(Duration.ofMinutes(10)));
        assertThatThrownBy(requested::complete).isInstanceOf(EnrollmentStateException.class);
        assertThatThrownBy(() -> primaryRow.countClaimAttempt()).isInstanceOf(EnrollmentStateException.class);
        assertThatThrownBy(() -> requested.fail().fail()).isInstanceOf(EnrollmentStateException.class);
        assertThatThrownBy(() -> primaryRow.complete().expire()).isInstanceOf(EnrollmentStateException.class);
        assertThat(primaryRow.expire().state()).isEqualTo(EnrollmentState.EXPIRED);
        assertThatThrownBy(() -> primaryRow.toBuilder().mfaTransactionId(null).build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aTransactionPastItsKeyProofBecomesThePrimaryEnrollmentRowTheCommitWrites() {
        AdmittedSession tablet = new AdmittedSession(SessionId.random(), new CustomerId("90359"), Channel.MOBILE,
                new DeviceId("tablet-2"), com.vpbank.dcp.auth.domain.enums.SessionStatus.NEED_TRUSTED_DEVICE);
        KeyExchangeStart start = KeyExchangeStart.builder()
                .enrollmentId(EnrollmentId.random())
                .newDeviceSession(tablet)
                .targetDeviceId(TrustedDeviceId.random())
                .deviceKey(new DeviceKey("{dev}", DevicePlatform.IOS))
                .serverPublicJwk("{pub}")
                .serverPrivateJwk("{priv}")
                .challengeDigest("digest")
                .build();
        EnrollmentTransaction started = EnrollmentTransaction.keyExchange(start);
        EnrollmentTransaction passed = started.countVerifyAttempt().markMfaRequired("mfa-1");

        DeviceEnrollment enrollment = DeviceEnrollment.fromTransaction(passed, T0.plusSeconds(600));

        assertThat(enrollment.id()).isEqualTo(passed.id());
        assertThat(enrollment.purpose()).isEqualTo(com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose.TRUST_DEVICE);
        assertThat(enrollment.state()).isEqualTo(EnrollmentState.MFA_REQUIRED);
        assertThat(enrollment.customerId()).isEqualTo(tablet.customerId());
        assertThat(enrollment.deviceId()).isEqualTo(tablet.deviceId());
        assertThat(enrollment.targetDeviceId()).isEqualTo(passed.targetDeviceId());
        assertThat(enrollment.mfaTransactionId()).isEqualTo("mfa-1");
        assertThat(enrollment.verifyAttempts()).isEqualTo(1);
        assertThat(enrollment.expiresAt()).isEqualTo(T0.plusSeconds(600));
        assertThat(enrollment.version()).isZero();
        assertThat(enrollment.complete().state()).isEqualTo(EnrollmentState.COMPLETED);

        assertThatThrownBy(() -> DeviceEnrollment.fromTransaction(started, T0.plusSeconds(600))).isInstanceOf(EnrollmentStateException.class);
    }
}
