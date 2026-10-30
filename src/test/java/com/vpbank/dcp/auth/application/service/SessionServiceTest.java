package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.application.service.SessionService.IssuedSession;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The common session actions the flows compose: issue, find by kind, consume once, end. */
class SessionServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-30T10:00:00Z");
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final DeviceId PHONE = new DeviceId("phone-1");
    private static final SessionId SESSION = new SessionId(UUID.fromString("00000000-0000-4000-8000-000000000001"));
    private static final OpaqueToken TOKEN = OpaqueToken.of(Channel.MOBILE, SESSION, "A".repeat(43));
    private static final String KENC = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"..\",\"y\":\"..\"}";

    private final InMemorySessionStore sessions = new InMemorySessionStore();
    private final TokenEnvelopeSealer sealer = mock(TokenEnvelopeSealer.class);
    private final OpaqueTokenGenerator tokens = mock(OpaqueTokenGenerator.class);
    private final SessionService service = new SessionService(sessions, sealer, tokens, () -> SESSION,
            new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20), Duration.ofSeconds(30)),
            DevicePolicy.standard(), Clock.fixed(NOW, ZoneOffset.UTC));

    @BeforeEach
    void tokenAndEnvelope() {
        when(tokens.next(eq(Channel.MOBILE), eq(SESSION))).thenReturn(TOKEN);
        when(sealer.seal(eq(KENC), eq(TOKEN), any())).thenReturn("jwe.compact");
    }

    @Test
    void issuesAFullSessionSealedToTheAppKeyAndFindsItAsActiveOnly() {
        IssuedSession issued = service.issueActive(service.newSessionId(), ALICE, PHONE, Channel.MOBILE, KENC);

        assertThat(issued.tokenEnvelope()).isEqualTo("jwe.compact");
        assertThat(issued.session().status()).isEqualTo(SessionStatus.ACTIVE);
        assertThat(issued.session().idleExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(issued.session().absoluteExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(20)));
        assertThat(issued.toString()).doesNotContain("jwe");
        assertThat(service.findLive(TOKEN)).map(StoredSession::session).contains(sessions.only());
        assertThat(service.findActive(TOKEN)).isPresent();
        assertThat(service.findRestricted(TOKEN)).isEmpty();
    }

    @Test
    void issuesARestrictedSessionWithTheFixedDeadlineAndFindsItAsRestrictedOnly() {
        IssuedSession issued = service.issueRestricted(SESSION, ALICE, PHONE, Channel.MOBILE, KENC);

        assertThat(issued.session().status()).isEqualTo(SessionStatus.NEED_TRUSTED_DEVICE);
        assertThat(issued.session().idleExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(10)));
        assertThat(issued.session().absoluteExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(10)));
        assertThat(service.findRestricted(TOKEN)).isPresent();
        assertThat(service.findActive(TOKEN)).isEmpty();
    }

    @Test
    void consumeWinsOnceAndEndRemovesWithoutAnAnswer() {
        service.issueRestricted(SESSION, ALICE, PHONE, Channel.MOBILE, KENC);
        StoredSession stored = service.findRestricted(TOKEN).orElseThrow();

        assertThat(service.consume(stored)).isTrue();
        assertThat(service.consume(stored)).isFalse(); // the second claimant loses
        assertThat(service.findLive(TOKEN)).isEmpty();

        service.issueActive(SESSION, ALICE, PHONE, Channel.MOBILE, KENC);
        service.end(service.findLive(TOKEN).orElseThrow());
        assertThat(sessions.rows).isEmpty();
    }
}
