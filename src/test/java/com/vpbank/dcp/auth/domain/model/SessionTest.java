package com.vpbank.dcp.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.exception.SessionStateException;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class SessionTest {
    private static final Instant T0 = Instant.parse("2026-10-25T10:00:00Z");
    private final SessionPolicy policy = new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20),
            Duration.ofSeconds(30));
    private final Session session = Session.start(SessionId.random(), new CustomerId("90359"),
            new DeviceId("dev-1"), Channel.MOBILE, T0, policy);

    @Test
    void startsActiveWithIdleAndAbsoluteDeadlines() {
        assertThat(session.status()).isEqualTo(SessionStatus.ACTIVE);
        assertThat(session.idleExpiresAt()).isEqualTo(T0.plus(Duration.ofMinutes(15)));
        assertThat(session.absoluteExpiresAt()).isEqualTo(T0.plus(Duration.ofMinutes(20)));
        assertThat(session.sessionVersion()).isZero();
        assertThat(session.isLive(T0.plusSeconds(1))).isTrue();
        assertThat(session.isLive(T0.plus(Duration.ofMinutes(15)))).isFalse();
    }

    @Test
    void extendSlidesIdleFromTheAdmissionTimeNeverPastAbsolute() {
        Instant admitted = T0.plus(Duration.ofMinutes(3));
        Session extended = session.extend(admitted, admitted.plusSeconds(1), policy);
        assertThat(extended.idleExpiresAt()).isEqualTo(admitted.plus(Duration.ofMinutes(15)));
        assertThat(extended.absoluteExpiresAt()).isEqualTo(session.absoluteExpiresAt());

        Instant late = T0.plus(Duration.ofMinutes(14));
        assertThat(session.extend(late, late, policy).idleExpiresAt()).isEqualTo(session.absoluteExpiresAt());
    }

    @Test
    void extendNeverShortensIdleAndKeepsTheVersion() {
        Instant admitted = T0.minusSeconds(10); // admitted just before creation (within skew): keeps old idle
        Session extended = session.extend(admitted, T0, policy);
        assertThat(extended.idleExpiresAt()).isEqualTo(session.idleExpiresAt());
        assertThat(extended.sessionVersion()).isEqualTo(session.sessionVersion());
    }

    @Test
    void anAdmissionTimeOutsideTheSkewIsRejected() {
        assertThatThrownBy(() -> session.extend(T0, T0.plusSeconds(31), policy))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> session.extend(T0.plusSeconds(31), T0, policy))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void expiredOrEndedSessionsCannotBeExtended() {
        Instant afterIdle = T0.plus(Duration.ofMinutes(16));
        assertThatThrownBy(() -> session.extend(afterIdle, afterIdle, policy)).isInstanceOf(SessionStateException.class);
        Session ended = session.end(T0);
        assertThat(ended.status()).isEqualTo(SessionStatus.ENDED);
        assertThat(ended.isLive(T0)).isFalse();
        assertThatThrownBy(() -> ended.end(T0)).isInstanceOf(SessionStateException.class);
    }

    @Test
    void policyAndDeadlinesAreChecked() {
        assertThatThrownBy(() -> new SessionPolicy(Duration.ofMinutes(20), Duration.ofMinutes(15), Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> session.toBuilder().idleExpiresAt(session.absoluteExpiresAt().plusSeconds(1)).build())
                .isInstanceOf(IllegalArgumentException.class);
    }
}
