package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.command.ExtendSessionCommand;
import com.vpbank.dcp.auth.application.result.ExtendSessionResult;
import com.vpbank.dcp.auth.application.command.LogoutCommand;
import com.vpbank.dcp.auth.application.result.LogoutResult;
import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class SessionServiceTest {
    private static final Instant T0 = Instant.parse("2026-10-25T10:00:00Z");
    private static final String DIGEST = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static final OpaqueToken TOKEN = new OpaqueToken("k1." + DIGEST);

    private final SessionPolicy policy = new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20),
            Duration.ofSeconds(30));
    private final InMemorySessionStore sessions = new InMemorySessionStore();
    private final MutableClock clock = new MutableClock(T0.plus(Duration.ofMinutes(5)));
    private final SessionService service = new SessionService(sessions, policy, clock);

    SessionServiceTest() {
        sessions.create(Session.start(SessionId.random(), new CustomerId("90359"), null, Channel.MOBILE, T0, policy), TOKEN);
    }

    @Test
    void resolvesALiveSessionWithoutTouchingIt() {
        assertThat(service.resolve(TOKEN)).isPresent()
                .hasValueSatisfying(summary -> assertThat(summary.customerId()).isEqualTo(new CustomerId("90359")));
        assertThat(sessions.only().sessionVersion()).isZero();

        clock.now = T0.plus(Duration.ofMinutes(15));
        assertThat(service.resolve(TOKEN)).isEmpty();
    }

    @Test
    void extendsFromTheAdmissionTimeAndBumpsTheVersion() {
        ExtendSessionResult result = service.extend(command(clock.now.minusSeconds(5)));

        assertThat(result).isInstanceOf(ExtendSessionResult.Extended.class);
        assertThat(((ExtendSessionResult.Extended) result).idleExpiresAt())
                .isEqualTo(clock.now.minusSeconds(5).plus(Duration.ofMinutes(15)));
        assertThat(sessions.only().sessionVersion()).isEqualTo(1);
    }

    @Test
    void aLostRaceIsRetriedWithTheSameAdmissionTimeThenReportedAsConflict() {
        sessions.concurrentBumps = 1;
        assertThat(service.extend(command(clock.now))).isInstanceOf(ExtendSessionResult.Extended.class);
        assertThat(sessions.only().sessionVersion()).isEqualTo(2);

        sessions.concurrentBumps = SessionService.EXTEND_ATTEMPTS;
        assertThat(service.extend(command(clock.now))).isInstanceOf(ExtendSessionResult.Conflict.class);
    }

    @Test
    void anUnknownExpiredOrOutOfSkewAdmissionIsGoneOrRejected() {
        assertThat(service.extend(ExtendSessionCommand.builder().lookupKeyVersion("k1").lookupDigest("B".repeat(43))
                .admittedAt(clock.now).routeId("accounts.read").build())).isInstanceOf(ExtendSessionResult.Gone.class);
        assertThat(service.extend(command(clock.now.minusSeconds(60)))).isInstanceOf(ExtendSessionResult.Rejected.class);
        clock.now = T0.plus(Duration.ofMinutes(21));
        assertThat(service.extend(command(clock.now))).isInstanceOf(ExtendSessionResult.Gone.class);
    }

    @Test
    void aRestrictedSessionResolvesButIsNeverExtended() {
        OpaqueToken restrictedToken = new OpaqueToken("k1." + "B".repeat(43));
        sessions.create(Session.startRestricted(SessionId.random(), new CustomerId("90359"), null, Channel.MOBILE, T0,
                com.vpbank.dcp.auth.domain.model.DevicePolicy.standard()), restrictedToken);

        assertThat(service.resolve(restrictedToken)).hasValueSatisfying(summary ->
                assertThat(summary.status()).isEqualTo(com.vpbank.dcp.auth.domain.model.SessionStatus.NEED_TRUSTED_DEVICE));
        assertThat(service.extend(ExtendSessionCommand.builder().lookupKeyVersion("k1").lookupDigest("B".repeat(43))
                .admittedAt(clock.now).routeId("accounts.read").build())).isInstanceOf(ExtendSessionResult.Gone.class);
        assertThat(service.logout(new LogoutCommand(restrictedToken))).isInstanceOf(LogoutResult.Ended.class);
    }

    @Test
    void logoutEndsTheSessionAndIsIdempotent() {
        assertThat(service.logout(new LogoutCommand(TOKEN))).isInstanceOf(LogoutResult.Ended.class);
        assertThat(sessions.rows).isEmpty();
        assertThat(service.logout(new LogoutCommand(TOKEN))).isInstanceOf(LogoutResult.Ended.class);
    }

    @Test
    void storeOutageIsUnavailable() {
        sessions.unavailable = true;
        assertThat(service.extend(command(clock.now))).isInstanceOf(ExtendSessionResult.Unavailable.class);
        assertThat(service.logout(new LogoutCommand(TOKEN))).isInstanceOf(LogoutResult.Unavailable.class);
    }

    private static ExtendSessionCommand command(Instant admittedAt) {
        return ExtendSessionCommand.builder().lookupKeyVersion("k1").lookupDigest(DIGEST).admittedAt(admittedAt)
                .routeId("accounts.read").admissionId("adm-1").build();
    }

    /** A clock the test moves by hand. */
    private static final class MutableClock extends Clock {
        Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
