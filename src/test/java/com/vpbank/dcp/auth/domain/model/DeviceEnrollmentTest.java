package com.vpbank.dcp.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.exception.EnrollmentStateException;
import com.vpbank.dcp.auth.domain.exception.SessionStateException;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class DeviceEnrollmentTest {
    private static final Instant T0 = Instant.parse("2026-10-25T10:00:00Z");
    private final DeviceEnrollment started = DeviceEnrollment.start(EnrollmentId.random(), new CustomerId("90359"),
            Channel.MOBILE, new DeviceId("tablet-2"), null, T0.plus(Duration.ofMinutes(10)));

    @Test
    void walksKeyExchangeToMfaRequiredToCompleted() {
        assertThat(started.state()).isEqualTo(EnrollmentState.KEY_EXCHANGE);
        assertThat(started.isOpen(T0)).isTrue();
        assertThat(started.isOpen(T0.plus(Duration.ofMinutes(10)))).isFalse();
        DeviceEnrollment counted = started.countAttempt().countAttempt();
        assertThat(counted.verifyAttempts()).isEqualTo(2);
        assertThat(counted.attemptsExhausted(EnrollmentPolicy.standard())).isFalse();
        assertThat(counted.countAttempt().attemptsExhausted(EnrollmentPolicy.standard())).isTrue();
        DeviceEnrollment mfa = counted.markMfaRequired("mfa-1");
        assertThat(mfa.state()).isEqualTo(EnrollmentState.MFA_REQUIRED);
        assertThat(mfa.mfaTransactionId()).isEqualTo("mfa-1");
        DeviceEnrollment done = mfa.complete();
        assertThat(done.state()).isEqualTo(EnrollmentState.COMPLETED);
        assertThat(done.isOpen(T0)).isFalse();
    }

    @Test
    void stepsOutOfOrderAreProgrammingErrorsAndTerminalStatesStayTerminal() {
        assertThatThrownBy(started::complete).isInstanceOf(EnrollmentStateException.class);
        assertThatThrownBy(() -> started.markMfaRequired("x").countAttempt()).isInstanceOf(EnrollmentStateException.class);
        assertThatThrownBy(() -> started.fail().fail()).isInstanceOf(EnrollmentStateException.class);
        assertThatThrownBy(() -> started.markMfaRequired("x").complete().expire()).isInstanceOf(EnrollmentStateException.class);
        assertThat(started.markMfaRequired("x").expire().state()).isEqualTo(EnrollmentState.EXPIRED);
        assertThatThrownBy(() -> started.toBuilder().state(EnrollmentState.MFA_REQUIRED).build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void onlyARestrictedSessionCarriesAnEnrollmentContextAndItRedactsKeys() {
        EnrollmentContext context = EnrollmentContext.builder().enrollmentId(started.id()).devicePublicJwk("{dev}")
                .platform(DevicePlatform.IOS).serverPublicJwk("{pub}").serverPrivateJwk("{PRIVATE}").challengeDigest("d").build();
        Session restricted = Session.startRestricted(SessionId.random(), new CustomerId("90359"), new DeviceId("tablet-2"),
                Channel.MOBILE, T0, DevicePolicy.standard());
        Session withContext = restricted.withEnrollment(context);
        assertThat(withContext.enrollment().keyProven()).isFalse();
        assertThat(withContext.withEnrollment(context.proven()).enrollment().keyProven()).isTrue();
        assertThat(context.toString()).doesNotContain("PRIVATE");

        Session active = Session.start(SessionId.random(), new CustomerId("90359"), null, Channel.MOBILE, T0,
                new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20), Duration.ofSeconds(30)));
        assertThatThrownBy(() -> active.withEnrollment(context)).isInstanceOf(SessionStateException.class);
    }
}
