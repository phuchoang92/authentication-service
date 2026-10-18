package com.vpbank.dcp.core.application.trusteddevice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.in.trusteddevice.ConfirmTrustedDeviceResult;
import com.vpbank.dcp.core.port.in.trusteddevice.InitTrustedDeviceResult;
import com.vpbank.dcp.core.port.in.trusteddevice.TrustedDeviceCaller;
import com.vpbank.dcp.core.port.in.trusteddevice.VerifyTrustedDeviceResult;
import com.vpbank.dcp.core.port.out.mfa.MfaCheckResult;
import com.vpbank.dcp.core.port.out.mfa.MfaStartResult;
import com.vpbank.dcp.core.port.out.mfa.MfaTransactions;
import com.vpbank.dcp.core.port.out.mfa.MfaUnavailableException;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.core.port.out.trusteddevice.DeviceKeyMaterial;
import com.vpbank.dcp.core.port.out.trusteddevice.KeyExchange;
import com.vpbank.dcp.core.port.out.trusteddevice.KeyExchangeStart;
import com.vpbank.dcp.core.port.out.trusteddevice.LoginKeys;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionStep;
import com.vpbank.dcp.core.port.out.trusteddevice.ServerKeyExchange;
import com.vpbank.dcp.core.port.out.trusteddevice.StoredRestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustActivationResult;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustTarget;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustedDeviceRecords;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustedDeviceRecordsUnavailableException;
import com.vpbank.dcp.core.port.out.trusteddevice.WrappedServerKey;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

class TrustedDeviceServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-18T00:00:00Z");
    private static final String TXN = "mfa-transaction-0000000000001";
    private final TrustedDeviceSessions sessions = mock(TrustedDeviceSessions.class);
    private final ServerKeyExchange keys = mock(ServerKeyExchange.class);
    private final MfaTransactions mfa = mock(MfaTransactions.class);
    private final TrustedDeviceRecords records = mock(TrustedDeviceRecords.class);
    private final TrustedSessionIssuer issuer = mock(TrustedSessionIssuer.class);
    private final TrustedDeviceService service =
            new TrustedDeviceService(sessions, keys, mfa, records, issuer, 3);

    private final Digest32 digest = Digest32.fromBytes(new byte[32]);
    private final TrustedDeviceCaller caller = new TrustedDeviceCaller(
            UUID.randomUUID(), "neo-mobile",
            "device-id-1234567890");
    private final SubjectId owner = new SubjectId(UUID.randomUUID());
    private final BindingId binding = new BindingId(UUID.randomUUID());
    private final KeyExchange exchange = new KeyExchange(new WrappedServerKey("w1", new byte[] {1}),
            "server-jwk", digest, "device-jwk", digest);

    // ---------- init ----------

    @Test
    void initStartsTheKeyExchangeForANewDeviceWithItsPresentedKey() {
        session(RestrictedSessionStep.OPEN, new TrustTarget.NewDevice());
        when(keys.begin(new DeviceKeyMaterial.Presented("device-jwk"), owner, "neo-mobile"))
                .thenReturn(new KeyExchangeStart.Started(exchange, "challenge-jwe"));
        when(sessions.beginKeyExchange(caller, exchange)).thenReturn(true);

        assertThat(service.init(caller, "device-jwk", NOW))
                .isEqualTo(new InitTrustedDeviceResult.Started("server-jwk", "challenge-jwe"));
    }

    /** "Giữ key cũ": a known device is challenged with its stored key and may not send another. */
    @Test
    void knownDeviceUsesItsStoredKeyAndCannotSubstituteOne() {
        session(RestrictedSessionStep.OPEN, new TrustTarget.KnownDevice(binding, digest, 1));
        StoredDeviceKey stored = new StoredDeviceKey(new byte[] {1}, digest);
        when(records.storedKey(owner, "neo-mobile", binding)).thenReturn(Optional.of(stored));
        when(keys.begin(new DeviceKeyMaterial.Stored(stored), owner, "neo-mobile"))
                .thenReturn(new KeyExchangeStart.Started(exchange, "challenge-jwe"));
        when(sessions.beginKeyExchange(caller, exchange)).thenReturn(true);

        assertThat(service.init(caller, null, NOW)).isInstanceOf(InitTrustedDeviceResult.Started.class);
        assertThat(service.init(caller, "another-device-jwk", NOW))
                .isInstanceOf(InitTrustedDeviceResult.Rejected.class);
    }

    @Test
    void newDeviceWithoutAKeyOrAnUnusableKeyIsRejected() {
        session(RestrictedSessionStep.OPEN, new TrustTarget.NewDevice());
        assertThat(service.init(caller, null, NOW)).isInstanceOf(InitTrustedDeviceResult.Rejected.class);

        when(keys.begin(any(), any(), any())).thenReturn(new KeyExchangeStart.InvalidDeviceKey());
        assertThat(service.init(caller, "bad-jwk", NOW)).isInstanceOf(InitTrustedDeviceResult.Rejected.class);
        verify(sessions, never()).beginKeyExchange(any(), any());
    }

    @Test
    void initRunsOnlyOnceAndOnlyFromOpen() {
        session(RestrictedSessionStep.OPEN, new TrustTarget.NewDevice());
        when(keys.begin(any(), any(), any())).thenReturn(new KeyExchangeStart.Started(exchange, "c"));
        when(sessions.beginKeyExchange(caller, exchange)).thenReturn(false);
        assertThat(service.init(caller, "device-jwk", NOW)).isInstanceOf(InitTrustedDeviceResult.Rejected.class);

        session(RestrictedSessionStep.KEY_EXCHANGE, new TrustTarget.NewDevice());
        assertThat(service.init(caller, "device-jwk", NOW)).isInstanceOf(InitTrustedDeviceResult.Rejected.class);

        when(sessions.current(caller)).thenReturn(Optional.empty());
        assertThat(service.init(caller, "device-jwk", NOW)).isInstanceOf(InitTrustedDeviceResult.Rejected.class);
    }

    @Test
    void initWhenTheDeviceStoreIsDownIsUnavailable() {
        session(RestrictedSessionStep.OPEN, new TrustTarget.KnownDevice(binding, digest, 1));
        when(records.storedKey(any(), any(), any()))
                .thenThrow(new TrustedDeviceRecordsUnavailableException(new RuntimeException()));

        assertThat(service.init(caller, null, NOW)).isInstanceOf(InitTrustedDeviceResult.Unavailable.class);
    }

    // ---------- verify ----------

    @Test
    void correctAnswerOpensTheMfaTransaction() {
        session(RestrictedSessionStep.KEY_EXCHANGE, new TrustTarget.NewDevice());
        when(sessions.recordVerifyAttempt(caller)).thenReturn(1);
        when(keys.answers(exchange, owner, "neo-mobile", "answer")).thenReturn(true);
        when(mfa.start(any())).thenReturn(new MfaStartResult.Started(TXN, NOW.plusSeconds(300)));
        when(sessions.recordMfaTransaction(caller, TXN)).thenReturn(true);

        assertThat(service.verify(caller, "answer", NOW))
                .isEqualTo(new VerifyTrustedDeviceResult.MfaRequired(TXN));
    }

    /** No MFA transaction exists until the device key is proven. */
    @Test
    void wrongAnswerCountsDownAndTheLastOneEndsTheSession() {
        session(RestrictedSessionStep.KEY_EXCHANGE, new TrustTarget.NewDevice());
        when(keys.answers(any(), any(), any(), any())).thenReturn(false);

        when(sessions.recordVerifyAttempt(caller)).thenReturn(1);
        assertThat(service.verify(caller, "guess", NOW))
                .isEqualTo(new VerifyTrustedDeviceResult.WrongChallenge(2));
        when(sessions.recordVerifyAttempt(caller)).thenReturn(3);
        assertThat(service.verify(caller, "guess", NOW)).isInstanceOf(VerifyTrustedDeviceResult.Rejected.class);
        verify(sessions).end(caller);
        verifyNoInteractions(mfa);
    }

    @Test
    void attemptsBeyondTheLimitAreRejectedBeforeTheAnswerIsChecked() {
        session(RestrictedSessionStep.KEY_EXCHANGE, new TrustTarget.NewDevice());
        when(sessions.recordVerifyAttempt(caller)).thenReturn(4);

        assertThat(service.verify(caller, "answer", NOW)).isInstanceOf(VerifyTrustedDeviceResult.Rejected.class);
        verify(keys, never()).answers(any(), any(), any(), any());
        verify(sessions).end(caller);
    }

    @Test
    void verifyRequiresInitAndRunsOnce() {
        session(RestrictedSessionStep.OPEN, new TrustTarget.NewDevice());
        assertThat(service.verify(caller, "answer", NOW)).isInstanceOf(VerifyTrustedDeviceResult.Rejected.class);
        session(RestrictedSessionStep.MFA, new TrustTarget.NewDevice());
        assertThat(service.verify(caller, "answer", NOW)).isInstanceOf(VerifyTrustedDeviceResult.Rejected.class);
        verify(sessions, never()).recordVerifyAttempt(any());
    }

    @Test
    void customerWithoutFaceEndsTheSessionAndMfaOutageKeepsIt() {
        session(RestrictedSessionStep.KEY_EXCHANGE, new TrustTarget.NewDevice());
        when(sessions.recordVerifyAttempt(caller)).thenReturn(1);
        when(keys.answers(any(), any(), any(), any())).thenReturn(true);

        when(mfa.start(any())).thenThrow(new MfaUnavailableException());
        assertThat(service.verify(caller, "answer", NOW)).isInstanceOf(VerifyTrustedDeviceResult.Unavailable.class);
        verify(sessions, never()).end(any());

        doReturn(new MfaStartResult.NoUsableFactor()).when(mfa).start(any());
        assertThat(service.verify(caller, "answer", NOW)).isInstanceOf(VerifyTrustedDeviceResult.NoUsableFactor.class);
        verify(sessions).end(caller);
    }

    // ---------- confirm ----------

    /** Exactly one confirm may commit: the session is ended before the trust is written. */
    @Test
    void passedMfaEndsTheSessionThenCommitsThenIssues() {
        StoredRestrictedSession session = session(RestrictedSessionStep.MFA, new TrustTarget.NewDevice());
        when(mfa.check(any())).thenReturn(new MfaCheckResult.Passed(digest));
        when(sessions.end(caller)).thenReturn(true);
        when(records.activate(any())).thenReturn(new TrustActivationResult.Activated(binding));
        ConfirmTrustedDeviceResult.Active active =
                new ConfirmTrustedDeviceResult.Active(mock(com.vpbank.dcp.core.port.out.session.PreparedSession.class));
        when(issuer.issue(session, binding, "device-id-1234567890", NOW)).thenReturn(active);

        assertThat(service.confirm(caller, NOW)).isSameAs(active);
        InOrder order = inOrder(sessions, records, issuer);
        order.verify(sessions).end(caller);
        order.verify(records).activate(any());
        order.verify(issuer).issue(eq(session), eq(binding), any(), eq(NOW));
    }

    @Test
    void confirmThatLostTheRaceNeverCommits() {
        session(RestrictedSessionStep.MFA, new TrustTarget.NewDevice());
        when(mfa.check(any())).thenReturn(new MfaCheckResult.Passed(digest));
        when(sessions.end(caller)).thenReturn(false);

        assertThat(service.confirm(caller, NOW)).isInstanceOf(ConfirmTrustedDeviceResult.Rejected.class);
        verifyNoInteractions(records, issuer);
    }

    @Test
    void pendingMfaKeepsTheSessionForAnotherConfirm() {
        session(RestrictedSessionStep.MFA, new TrustTarget.NewDevice());
        when(mfa.check(any())).thenReturn(new MfaCheckResult.Pending());

        assertThat(service.confirm(caller, NOW)).isInstanceOf(ConfirmTrustedDeviceResult.MfaPending.class);
        verify(sessions, never()).end(any());
    }

    /** A forged receipt is never read as pending: it ends the attempt. */
    @Test
    void failedOrForgedOrExpiredMfaEndsTheSession() {
        session(RestrictedSessionStep.MFA, new TrustTarget.NewDevice());
        when(mfa.check(any())).thenReturn(new MfaCheckResult.InvalidReceipt());
        assertThat(service.confirm(caller, NOW)).isInstanceOf(ConfirmTrustedDeviceResult.Rejected.class);
        when(mfa.check(any())).thenReturn(new MfaCheckResult.Failed());
        assertThat(service.confirm(caller, NOW)).isInstanceOf(ConfirmTrustedDeviceResult.Rejected.class);
        when(mfa.check(any())).thenReturn(new MfaCheckResult.Expired());
        assertThat(service.confirm(caller, NOW)).isInstanceOf(ConfirmTrustedDeviceResult.Expired.class);
        verifyNoInteractions(records);
    }

    @Test
    void confirmRequiresVerifyAndMfaOutageIsUnavailable() {
        session(RestrictedSessionStep.KEY_EXCHANGE, new TrustTarget.NewDevice());
        assertThat(service.confirm(caller, NOW)).isInstanceOf(ConfirmTrustedDeviceResult.Rejected.class);
        verifyNoInteractions(mfa);

        session(RestrictedSessionStep.MFA, new TrustTarget.NewDevice());
        when(mfa.check(any())).thenThrow(new MfaUnavailableException());
        assertThat(service.confirm(caller, NOW)).isInstanceOf(ConfirmTrustedDeviceResult.Unavailable.class);
        verify(sessions, never()).end(any());
    }

    private StoredRestrictedSession session(RestrictedSessionStep step, TrustTarget target) {
        StoredRestrictedSession session = new StoredRestrictedSession(UUID.randomUUID(),
                UUID.randomUUID(), owner, new CustomerNumber("CUST-1"), 3, "neo-mobile", target,
                digest, new LoginKeys("request-jwk", digest, "response-jwk"), "ANDROID",
                UUID.randomUUID(), NOW.plusSeconds(600), step, 0,
                step == RestrictedSessionStep.OPEN ? null : exchange,
                step == RestrictedSessionStep.MFA ? TXN : null);
        when(sessions.current(caller)).thenReturn(Optional.of(session));
        return session;
    }
}
