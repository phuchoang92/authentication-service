package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.auth.application.command.ConfirmEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.InitEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.VerifyEnrollmentCommand;
import com.vpbank.dcp.auth.application.port.out.exception.InvalidEncryptionKeyException;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.ChallengeSealer;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CheckResult;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CreateResult;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.ServerKeyPairGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import com.vpbank.dcp.auth.application.port.out.model.OpenedChallenge;
import com.vpbank.dcp.auth.application.port.out.model.ServerKeyPair;
import com.vpbank.dcp.auth.application.result.ConfirmEnrollmentResult;
import com.vpbank.dcp.auth.application.result.InitEnrollmentResult;
import com.vpbank.dcp.auth.application.result.VerifyEnrollmentResult;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DeviceEnrollmentServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00Z");
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final DeviceId PHONE = new DeviceId("phone-1");
    private static final DeviceId TABLET = new DeviceId("tablet-2");
    private static final OpaqueToken RESTRICTED = new OpaqueToken("s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000002:" + "B".repeat(43));
    private static final OpaqueToken NEW_TOKEN = new OpaqueToken("s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000003:" + "C".repeat(43));
    private static final EnrollmentId ENROLLMENT = EnrollmentId.random();
    private static final byte[] CHALLENGE = "0123456789abcdef0123456789abcdef".getBytes();
    private static final String DEVICE_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"dev\"}";

    private final InMemorySessionStore sessions = new InMemorySessionStore();
    private final InMemoryEnrollmentRepository enrollments = new InMemoryEnrollmentRepository();
    private final InMemoryTrustedDeviceRepository devices = new InMemoryTrustedDeviceRepository();
    private final MfaTransactionPort mfa = mock(MfaTransactionPort.class);
    private final ServerKeyPairGenerator serverKeys = mock(ServerKeyPairGenerator.class);
    private final ChallengeSealer challenges = mock(ChallengeSealer.class);
    private final TokenEnvelopeSealer sealer = mock(TokenEnvelopeSealer.class);
    private final OpaqueTokenGenerator tokens = mock(OpaqueTokenGenerator.class);
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final TrustedDeviceService trustedDevices = new TrustedDeviceService(devices, DevicePolicy.standard(),
            TrustedDeviceId::random, clock);
    private final SessionService sessionService = new SessionService(sessions, sealer, tokens, SessionId::random,
            new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20), Duration.ofSeconds(30)),
            DevicePolicy.standard(), clock);
    private final DeviceEnrollmentService service = new DeviceEnrollmentService(sessionService, enrollments, trustedDevices,
            mfa, serverKeys, challenges, () -> ENROLLMENT, EnrollmentPolicy.standard(), clock);

    @BeforeEach
    void aliceHasAPrimaryPhoneAndATabletWithARestrictedSession() {
        TrustedDevice phone = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, PHONE,
                DevicePlatform.ANDROID, null, NOW.minusSeconds(3600), DevicePolicy.standard());
        devices.rows.put(phone.id(), phone);
        devices.primaries.put(new InMemoryTrustedDeviceRepository.Key(ALICE, Channel.MOBILE), phone.id());
        sessions.create(Session.startRestricted(SessionId.random(), ALICE, TABLET, Channel.MOBILE, NOW, DevicePolicy.standard()),
                RESTRICTED);
        when(serverKeys.next()).thenReturn(new ServerKeyPair("{srv-pub}", "{srv-priv}"));
        when(challenges.newChallenge()).thenReturn(CHALLENGE);
        when(challenges.sealChallenge(eq(DEVICE_KEY), eq(ENROLLMENT), eq(CHALLENGE))).thenReturn("jwe.challenge");
        when(challenges.openResponse(eq("{srv-priv}"), eq("jwe.answer"))).thenReturn(Optional.of(new OpenedChallenge(ENROLLMENT, CHALLENGE)));
        when(mfa.create(any())).thenReturn(new CreateResult.Created("mfa-1", NOW.plus(Duration.ofMinutes(5))));
        when(tokens.next(any(), any())).thenReturn(NEW_TOKEN);
        when(sealer.seal(eq("{app-kenc}"), eq(NEW_TOKEN), any())).thenReturn("jwe.token");
    }

    @Test
    void initHandsOutKsrvAndASealedChallengeAndRemembersTheContextInTheSession() {
        InitEnrollmentResult result = service.init(new InitEnrollmentCommand(RESTRICTED, DEVICE_KEY, DevicePlatform.IOS));

        assertThat(result).isInstanceOf(InitEnrollmentResult.KeyExchange.class);
        InitEnrollmentResult.KeyExchange exchange = (InitEnrollmentResult.KeyExchange) result;
        assertThat(exchange.enrollmentId()).isEqualTo(ENROLLMENT);
        assertThat(exchange.serverPublicJwk()).isEqualTo("{srv-pub}");
        assertThat(exchange.challenge()).isEqualTo("jwe.challenge");
        assertThat(exchange.expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(10)));
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.KEY_EXCHANGE);
        Session session = sessions.findByToken(RESTRICTED).orElseThrow().session();
        assertThat(session.enrollment().serverPrivateJwk()).isEqualTo("{srv-priv}");
        assertThat(session.enrollment().keyProven()).isFalse();
        assertThat(session.enrollment().platform()).isEqualTo(DevicePlatform.IOS);

        assertThat(service.init(new InitEnrollmentCommand(RESTRICTED, DEVICE_KEY, DevicePlatform.IOS)))
                .isInstanceOf(InitEnrollmentResult.Conflict.class); // init runs once
    }

    @Test
    void anUnknownDeviceMustSendAUsableKeyAndPlatformWhileAKnownDeviceReusesItsStoredKey() {
        assertThat(service.init(new InitEnrollmentCommand(RESTRICTED, null, null)))
                .isInstanceOf(InitEnrollmentResult.DeviceKeyRequired.class);
        when(challenges.sealChallenge(eq("bad"), any(), any())).thenThrow(new InvalidEncryptionKeyException("not P-256"));
        assertThat(service.init(new InitEnrollmentCommand(RESTRICTED, "bad", DevicePlatform.IOS)))
                .isInstanceOf(InitEnrollmentResult.DeviceKeyRequired.class);
        assertThat(enrollments.rows).isEmpty();

        // The phone (trusted, with a stored key) logs in on a reinstall-free second install: it is not primary? No — it is;
        // so make the tablet known with a stored key instead and check the stored key is used.
        TrustedDevice knownTablet = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, TABLET,
                DevicePlatform.IOS, "{stored-key}", NOW.minusSeconds(60), DevicePolicy.standard());
        devices.rows.put(knownTablet.id(), knownTablet);
        when(challenges.sealChallenge(eq("{stored-key}"), eq(ENROLLMENT), eq(CHALLENGE))).thenReturn("jwe.stored");
        InitEnrollmentResult result = service.init(new InitEnrollmentCommand(RESTRICTED, null, null));
        assertThat(((InitEnrollmentResult.KeyExchange) result).challenge()).isEqualTo("jwe.stored");
        assertThat(enrollments.only().targetDeviceId()).isEqualTo(knownTablet.id());
    }

    @Test
    void verifyCountsTheAttemptOpensTheMfaTransactionOnlyAfterTheKeyIsProven() {
        service.init(new InitEnrollmentCommand(RESTRICTED, DEVICE_KEY, DevicePlatform.IOS));

        VerifyEnrollmentResult wrong = service.verify(new VerifyEnrollmentCommand(RESTRICTED, "jwe.garbage"));
        assertThat(wrong).isEqualTo(new VerifyEnrollmentResult.WrongChallenge(2));
        verifyNoInteractions(mfa);
        assertThat(enrollments.only().verifyAttempts()).isEqualTo(1);

        VerifyEnrollmentResult ok = service.verify(new VerifyEnrollmentCommand(RESTRICTED, "jwe.answer"));
        assertThat(ok).isEqualTo(new VerifyEnrollmentResult.MfaRequired("mfa-1", NOW.plus(Duration.ofMinutes(5))));
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.MFA_REQUIRED);
        assertThat(sessions.findByToken(RESTRICTED).orElseThrow().session().enrollment().keyProven()).isTrue();
        var request = org.mockito.ArgumentCaptor.forClass(MfaTransactionRequest.class);
        verify(mfa).create(request.capture());
        assertThat(request.getValue().customerId()).isEqualTo(ALICE);
        assertThat(request.getValue().authOperationId()).isEqualTo(ENROLLMENT);
        assertThat(request.getValue().contextDigest()).isEqualTo(EnrollmentDigests.contextDigest(enrollments.only()));

        assertThat(service.verify(new VerifyEnrollmentCommand(RESTRICTED, "jwe.answer")))
                .isInstanceOf(VerifyEnrollmentResult.Conflict.class); // verify runs once
    }

    @Test
    void theThirdWrongAnswerEndsTheEnrollmentAndTheRestrictedSession() {
        service.init(new InitEnrollmentCommand(RESTRICTED, DEVICE_KEY, DevicePlatform.IOS));
        assertThat(service.verify(new VerifyEnrollmentCommand(RESTRICTED, "x"))).isEqualTo(new VerifyEnrollmentResult.WrongChallenge(2));
        assertThat(service.verify(new VerifyEnrollmentCommand(RESTRICTED, "x"))).isEqualTo(new VerifyEnrollmentResult.WrongChallenge(1));
        assertThat(service.verify(new VerifyEnrollmentCommand(RESTRICTED, "x"))).isEqualTo(new VerifyEnrollmentResult.WrongChallenge(0));
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.FAILED);
        assertThat(sessions.findByToken(RESTRICTED)).isEmpty();
        assertThat(service.verify(new VerifyEnrollmentCommand(RESTRICTED, "jwe.answer")))
                .isInstanceOf(VerifyEnrollmentResult.SessionGone.class);
    }

    @Test
    void noUsableFactorEndsEverythingAndAnMfaOutageChangesNothing() {
        service.init(new InitEnrollmentCommand(RESTRICTED, DEVICE_KEY, DevicePlatform.IOS));
        doThrow(new PartnerUnavailableException("MFA")).when(mfa).create(any());
        assertThat(service.verify(new VerifyEnrollmentCommand(RESTRICTED, "jwe.answer")))
                .isInstanceOf(VerifyEnrollmentResult.Unavailable.class);
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.KEY_EXCHANGE); // the attempt is counted, nothing else
        assertThat(enrollments.only().verifyAttempts()).isEqualTo(1);

        doReturn(new CreateResult.NoUsableFactor()).when(mfa).create(any());
        assertThat(service.verify(new VerifyEnrollmentCommand(RESTRICTED, "jwe.answer")))
                .isInstanceOf(VerifyEnrollmentResult.NoUsableFactor.class);
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.FAILED);
        assertThat(sessions.findByToken(RESTRICTED)).isEmpty();
    }

    @Test
    void confirmPassedCommitsTrustMakesTheTabletPrimaryEndsTheRestrictedSessionAndIssuesAnActiveOne() {
        service.init(new InitEnrollmentCommand(RESTRICTED, DEVICE_KEY, DevicePlatform.IOS));
        service.verify(new VerifyEnrollmentCommand(RESTRICTED, "jwe.answer"));
        when(mfa.check(argThat(check -> check.mfaTransactionId().equals("mfa-1") && check.authOperationId().equals(ENROLLMENT)))).thenReturn(new CheckResult.Passed("receipt-sha"));

        ConfirmEnrollmentResult result = service.confirm(new ConfirmEnrollmentCommand(RESTRICTED, "{app-kenc}"));

        assertThat(result).isInstanceOf(ConfirmEnrollmentResult.Trusted.class);
        ConfirmEnrollmentResult.Trusted trusted = (ConfirmEnrollmentResult.Trusted) result;
        assertThat(trusted.tokenEnvelope()).isEqualTo("jwe.token");
        assertThat(trusted.idleExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(sessions.findByToken(RESTRICTED)).isEmpty();
        Session active = sessions.findByToken(NEW_TOKEN).orElseThrow().session();
        assertThat(active.status()).isEqualTo(SessionStatus.ACTIVE);
        assertThat(active.deviceId()).isEqualTo(TABLET);
        assertThat(devices.confirmations.getFirst().enrollment().state()).isEqualTo(EnrollmentState.COMPLETED);
        TrustedDevice tablet = devices.findLive(ALICE, Channel.MOBILE, TABLET).orElseThrow();
        assertThat(tablet.publicKey()).isEqualTo(DEVICE_KEY);
        assertThat(tablet.platform()).isEqualTo(DevicePlatform.IOS);
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).contains(tablet.id());
        assertThat(devices.findLive(ALICE, Channel.MOBILE, PHONE)).isPresent(); // the old primary stays trusted
        assertThat(devices.confirmations.getFirst().receiptDigest()).isEqualTo("receipt-sha");
        assertThat(devices.confirmations.getFirst().replaced()).isNull();

        assertThat(service.confirm(new ConfirmEnrollmentCommand(RESTRICTED, "{app-kenc}")))
                .isInstanceOf(ConfirmEnrollmentResult.SessionGone.class);
    }

    @Test
    void aReinstallReplacesTheOldRowOfTheSameInstallation() {
        TrustedDevice oldTablet = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, TABLET,
                DevicePlatform.IOS, "{old-key}", NOW.minusSeconds(60), DevicePolicy.standard());
        devices.rows.put(oldTablet.id(), oldTablet);
        service.init(new InitEnrollmentCommand(RESTRICTED, DEVICE_KEY, DevicePlatform.IOS)); // a new key: reinstall
        service.verify(new VerifyEnrollmentCommand(RESTRICTED, "jwe.answer"));
        when(mfa.check(any())).thenReturn(new CheckResult.Passed("r"));

        service.confirm(new ConfirmEnrollmentCommand(RESTRICTED, "{app-kenc}"));

        assertThat(devices.rows.get(oldTablet.id()).status()).isEqualTo(DeviceStatus.EXPIRED);
        assertThat(devices.findLive(ALICE, Channel.MOBILE, TABLET).orElseThrow().publicKey()).isEqualTo(DEVICE_KEY);
        assertThat(devices.confirmations.getFirst().replaced().id()).isEqualTo(oldTablet.id());
    }

    @Test
    void confirmMapsPendingFailedExpiredRejectedAndOutage() {
        service.init(new InitEnrollmentCommand(RESTRICTED, DEVICE_KEY, DevicePlatform.IOS));
        service.verify(new VerifyEnrollmentCommand(RESTRICTED, "jwe.answer"));

        when(mfa.check(any())).thenReturn(new CheckResult.Pending());
        assertThat(service.confirm(new ConfirmEnrollmentCommand(RESTRICTED, "{app-kenc}"))).isInstanceOf(ConfirmEnrollmentResult.MfaPending.class);
        when(mfa.check(any())).thenReturn(new CheckResult.Rejected());
        assertThat(service.confirm(new ConfirmEnrollmentCommand(RESTRICTED, "{app-kenc}"))).isInstanceOf(ConfirmEnrollmentResult.Rejected.class);
        doThrow(new PartnerUnavailableException("MFA")).when(mfa).check(any());
        assertThat(service.confirm(new ConfirmEnrollmentCommand(RESTRICTED, "{app-kenc}"))).isInstanceOf(ConfirmEnrollmentResult.Unavailable.class);
        assertThat(sessions.findByToken(RESTRICTED)).isPresent();
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.MFA_REQUIRED);
        verify(tokens, never()).next(any(), any());

        doReturn(new CheckResult.Failed()).when(mfa).check(any());
        assertThat(service.confirm(new ConfirmEnrollmentCommand(RESTRICTED, "{app-kenc}"))).isInstanceOf(ConfirmEnrollmentResult.MfaFailed.class);
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.FAILED);
        assertThat(sessions.findByToken(RESTRICTED)).isEmpty();
        assertThat(devices.findLive(ALICE, Channel.MOBILE, TABLET)).isEmpty();
    }

    @Test
    void confirmBeforeVerifyAndAnActiveSessionAreConflicts() {
        service.init(new InitEnrollmentCommand(RESTRICTED, DEVICE_KEY, DevicePlatform.IOS));
        assertThat(service.confirm(new ConfirmEnrollmentCommand(RESTRICTED, "{app-kenc}"))).isInstanceOf(ConfirmEnrollmentResult.Conflict.class);
        verifyNoInteractions(mfa);

        OpaqueToken active = new OpaqueToken("s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000004:" + "D".repeat(43));
        sessions.create(Session.start(SessionId.random(), ALICE, PHONE, Channel.MOBILE, NOW,
                new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20), Duration.ofSeconds(30))), active);
        assertThat(service.init(new InitEnrollmentCommand(active, DEVICE_KEY, DevicePlatform.ANDROID))).isInstanceOf(InitEnrollmentResult.SessionGone.class);
    }
}
