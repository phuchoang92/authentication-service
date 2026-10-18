package com.vpbank.dcp.core.application.trusteddevice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.trusteddevice.LoginKeys;
import com.vpbank.dcp.core.port.in.trusteddevice.TrustedDeviceCaller;
import com.vpbank.dcp.core.port.out.trusteddevice.PreparedRestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionStep;
import com.vpbank.dcp.core.port.out.trusteddevice.StoredRestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionCryptography;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionStore;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustTarget;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class TrustedDeviceSessionsTest {
    private final RestrictedSessionCryptography cryptography = mock(RestrictedSessionCryptography.class);
    private final RestrictedSessionStore store = mock(RestrictedSessionStore.class);
    private final Instant now = Instant.parse("2026-10-18T00:00:00Z");
    private final UUID generation = UUID.randomUUID();
    private final RestrictedSession session = new RestrictedSession(UUID.randomUUID(),
            new SubjectId(UUID.randomUUID()), new CustomerNumber("CUST-1"), 3, "neo-mobile",
            new TrustTarget.NewDevice(), "device-id-1234567890",
            new LoginKeys("request-jwk", Digest32.fromBytes(new byte[32]), "response-jwk"), "ANDROID",
            generation);
    private final TrustedDeviceSessions sessions =
            new TrustedDeviceSessions(cryptography, store, Duration.ofMinutes(10));

    @Test
    void opensForTheConfiguredLifetime() {
        when(store.currentGeneration()).thenReturn(Optional.of(generation));
        PreparedRestrictedSession prepared = prepared(now.plus(Duration.ofMinutes(10)));
        when(cryptography.prepare(session, now.plus(Duration.ofMinutes(10))))
                .thenReturn(prepared);
        when(store.create(prepared)).thenReturn(true);

        assertThat(sessions.open(session, now))
                .isEqualTo(new RestrictedSessionResult.Opened(prepared));
    }

    /** A Valkey restart since the login's replay markers were reserved must stop the login. */
    @Test
    void changedGenerationNeverIssuesAToken() {
        when(store.currentGeneration()).thenReturn(Optional.of(UUID.randomUUID()));

        assertThat(sessions.open(session, now))
                .isInstanceOf(RestrictedSessionResult.Unavailable.class);
        verifyNoInteractions(cryptography);
        verify(store, never()).create(any());
    }

    @Test
    void unknownGenerationNeverIssuesAToken() {
        when(store.currentGeneration()).thenReturn(Optional.empty());

        assertThat(sessions.open(session, now))
                .isInstanceOf(RestrictedSessionResult.Unavailable.class);
        verifyNoInteractions(cryptography);
    }

    /** A token whose session was not stored must never be delivered. */
    @Test
    void sessionThatCouldNotBeStoredIsNotDelivered() {
        when(store.currentGeneration()).thenReturn(Optional.of(generation));
        PreparedRestrictedSession prepared = prepared(now.plus(Duration.ofMinutes(10)));
        when(cryptography.prepare(any(), any())).thenReturn(prepared);
        when(store.create(prepared)).thenReturn(false);

        assertThat(sessions.open(session, now))
                .isInstanceOf(RestrictedSessionResult.Unavailable.class);
    }

    @Test
    void lifetimeOutsideOneToThirtyMinutesFailsStartup() {
        assertThatThrownBy(() -> new TrustedDeviceSessions(cryptography, store, Duration.ofSeconds(59)))
                .isInstanceOf(InvalidTrustedDevicePolicyException.class);
        assertThatThrownBy(() -> new TrustedDeviceSessions(cryptography, store, Duration.ofMinutes(31)))
                .isInstanceOf(InvalidTrustedDevicePolicyException.class);
    }

    /** The BFF's assertion must name the channel and device that logged in. */
    @Test
    void currentOnlyMatchesTheSameChannelDeviceAndGeneration() {
        Digest32 deviceDigest = Digest32.fromBytes(new byte[32]);
        UUID sessionId = UUID.randomUUID();
        StoredRestrictedSession stored = new StoredRestrictedSession(UUID.randomUUID(),
                session.operationId(), session.owner(), session.customerNumber(), 3, "neo-mobile",
                new TrustTarget.NewDevice(), deviceDigest, session.keys(), "ANDROID", generation,
                now.plusSeconds(600), RestrictedSessionStep.OPEN, 0, null, null);
        when(store.find(sessionId)).thenReturn(Optional.of(stored));
        when(store.currentGeneration()).thenReturn(Optional.of(generation));
        when(cryptography.deviceIdDigest(session.owner(), "neo-mobile", "device-id-1234567890"))
                .thenReturn(deviceDigest);
        when(cryptography.deviceIdDigest(session.owner(), "neo-mobile", "other-device-1234567"))
                .thenReturn(Digest32.fromBytes(new byte[] {
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}));

        assertThat(sessions.current(new TrustedDeviceCaller(sessionId, "neo-mobile",
                "device-id-1234567890"))).contains(stored);
        assertThat(sessions.current(new TrustedDeviceCaller(sessionId, "other-channel",
                "device-id-1234567890"))).isEmpty();
        assertThat(sessions.current(new TrustedDeviceCaller(sessionId, "neo-mobile",
                "other-device-1234567"))).isEmpty();
        when(store.currentGeneration()).thenReturn(Optional.of(UUID.randomUUID()));
        assertThat(sessions.current(new TrustedDeviceCaller(sessionId, "neo-mobile",
                "device-id-1234567890"))).isEmpty();
    }

    private PreparedRestrictedSession prepared(Instant expiresAt) {
        Digest32 digest = Digest32.fromBytes(new byte[32]);
        return new PreparedRestrictedSession(session, UUID.randomUUID(),
                digest, digest, expiresAt,
                "envelope", "receipt");
    }
}
