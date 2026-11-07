package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.domain.model.DeviceInstallation;
import com.vpbank.dcp.auth.domain.model.DomainFixtures;
import com.vpbank.dcp.auth.domain.model.NewSession;
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
import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import com.vpbank.dcp.auth.application.port.out.model.OpenedChallenge;
import com.vpbank.dcp.auth.application.port.out.model.ServerKeyPair;
import com.vpbank.dcp.auth.application.port.out.model.TrustConfirmation;
import com.vpbank.dcp.auth.application.result.ConfirmEnrollmentResult;
import com.vpbank.dcp.auth.application.result.InitEnrollmentResult;
import com.vpbank.dcp.auth.application.result.VerifyEnrollmentResult;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
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

/**
 * Alice has a primary phone; her tablet logs in on a restricted session and enrolls itself with FACE. The steps
 * share a transaction in the cache (slice 11); SQL sees only the trust commit.
 */
class DeviceEnrollmentFlowTest {
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00Z");
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final DeviceId PHONE = new DeviceId("phone-1");
    private static final DeviceId TABLET = new DeviceId("tablet-2");
    private static final OpaqueToken RESTRICTED = new OpaqueToken("s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000002:" + "B".repeat(43));
    /** The tablet's restricted session as the BFF admits it (slice 11): same session ID as the token above. */
    private static final AdmittedSession TABLET_SESSION = new AdmittedSession(RESTRICTED.sessionId(), ALICE,
            Channel.MOBILE, TABLET, SessionStatus.NEED_TRUSTED_DEVICE);
    private static final OpaqueToken NEW_TOKEN = new OpaqueToken("s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000003:" + "C".repeat(43));
    private static final EnrollmentId ENROLLMENT = EnrollmentId.random();
    private static final byte[] CHALLENGE = "0123456789abcdef0123456789abcdef".getBytes();
    private static final String DEVICE_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"dev\"}";
    private static final Duration ENROLLMENT_LIFETIME = Duration.ofMinutes(10);

    private final InMemorySessionStore sessions = new InMemorySessionStore();
    private final InMemoryTransactionStore transactions = new InMemoryTransactionStore();
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
    private final EnrollmentTransactions enrollmentTransactions =
            new EnrollmentTransactions(transactions, ENROLLMENT_LIFETIME, clock);
    private final InitEnrollmentService initEnrollment = new InitEnrollmentService(enrollmentTransactions,
            trustedDevices, serverKeys, challenges, () -> ENROLLMENT);
    private final VerifyEnrollmentService verifyEnrollment = new VerifyEnrollmentService(sessionService,
            enrollmentTransactions, challenges, mfa, EnrollmentPolicy.standard());
    private final ConfirmEnrollmentService confirmEnrollment = new ConfirmEnrollmentService(sessionService,
            enrollmentTransactions, trustedDevices, mfa);

    @BeforeEach
    void aliceHasAPrimaryPhoneAndATabletWithARestrictedSession() {
        TrustedDevice phone = DomainFixtures.trustedDevice(new DeviceInstallation(ALICE, Channel.MOBILE, PHONE),
                DevicePlatform.ANDROID, null, NOW.minusSeconds(3600));
        devices.rows.put(phone.id(), phone);
        devices.primaries.put(new InMemoryTrustedDeviceRepository.Key(ALICE, Channel.MOBILE), phone.id());
        NewSession tabletStart = DomainFixtures.mobileSession(RESTRICTED.sessionId(), ALICE, TABLET, NOW);
        sessions.create(Session.startRestricted(tabletStart, DevicePolicy.standard()), RESTRICTED);
        when(serverKeys.next()).thenReturn(new ServerKeyPair("{srv-pub}", "{srv-priv}"));
        when(challenges.newChallenge()).thenReturn(CHALLENGE);
        when(challenges.sealChallenge(eq(DEVICE_KEY), eq(ENROLLMENT), eq(CHALLENGE))).thenReturn("jwe.challenge");
        when(challenges.openResponse(eq("{srv-priv}"), eq("jwe.answer"))).thenReturn(Optional.of(new OpenedChallenge(ENROLLMENT, CHALLENGE)));
        when(mfa.create(any())).thenReturn(new CreateResult.Created("mfa-1", NOW.plus(Duration.ofMinutes(5))));
        when(tokens.next(any(), any())).thenReturn(NEW_TOKEN);
        when(sealer.seal(eq("{app-kenc}"), eq(NEW_TOKEN), any())).thenReturn("jwe.token");
    }

    @Test
    void initHandsOutKsrvAndASealedChallengeAndKeepsTheContextInTheCacheNotTheSession() {
        InitEnrollmentResult result = initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS));

        assertThat(result).isInstanceOf(InitEnrollmentResult.KeyExchange.class);
        InitEnrollmentResult.KeyExchange exchange = (InitEnrollmentResult.KeyExchange) result;
        assertThat(exchange.enrollmentId()).isEqualTo(ENROLLMENT);
        assertThat(exchange.serverPublicJwk()).isEqualTo("{srv-pub}");
        assertThat(exchange.challenge()).isEqualTo("jwe.challenge");
        assertThat(exchange.expiresAt()).isEqualTo(NOW.plus(ENROLLMENT_LIFETIME));

        CacheTransaction<EnrollmentTransaction> transaction = transactions.only();
        assertThat(transaction.kind().purpose()).isEqualTo("enrollment");
        assertThat(transaction.id()).isEqualTo("MOBILE:90359:tablet-2");
        assertThat(transaction.expiresAt()).isEqualTo(NOW.plus(ENROLLMENT_LIFETIME));
        assertThat(transaction.payload().state()).isEqualTo(EnrollmentState.KEY_EXCHANGE);
        assertThat(transaction.payload().serverPrivateJwk()).isEqualTo("{srv-priv}");
        assertThat(transaction.payload().platform()).isEqualTo(DevicePlatform.IOS);
        assertThat(transaction.payload().belongsTo(TABLET_SESSION)).isTrue();
        assertThat(transaction.payload().challengeDigest()).isEqualTo(EnrollmentDigests.digest(CHALLENGE));
        // The restricted session is left as it was; nothing goes to SQL before the commit.
        assertThat(sessions.findByToken(RESTRICTED).orElseThrow().session().sessionVersion()).isZero();
        assertThat(devices.confirmations).isEmpty();

        assertThat(initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS)))
                .isInstanceOf(InitEnrollmentResult.Conflict.class); // init runs once per session
    }

    @Test
    void aNewLoginOnTheSameDeviceStartsOverAndTheEarlierLoginCanNoLongerContinue() {
        initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS));
        EnrollmentId secondEnrollment = EnrollmentId.random();
        InitEnrollmentService secondInit = new InitEnrollmentService(enrollmentTransactions, trustedDevices,
                serverKeys, challenges, () -> secondEnrollment);
        AdmittedSession laterLogin = new AdmittedSession(SessionId.random(), ALICE, Channel.MOBILE, TABLET,
                SessionStatus.NEED_TRUSTED_DEVICE);
        when(challenges.sealChallenge(eq(DEVICE_KEY), eq(secondEnrollment), eq(CHALLENGE))).thenReturn("jwe.challenge.2");

        InitEnrollmentResult restarted = secondInit.init(new InitEnrollmentCommand(laterLogin, DEVICE_KEY, DevicePlatform.IOS));

        assertThat(restarted).isInstanceOf(InitEnrollmentResult.KeyExchange.class);
        assertThat(transactions.rows).hasSize(1);
        assertThat(payload(transactions).id()).isEqualTo(secondEnrollment);
        assertThat(payload(transactions).belongsTo(laterLogin)).isTrue();
        assertThat(verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer")))
                .isInstanceOf(VerifyEnrollmentResult.Conflict.class);
        verifyNoInteractions(mfa);
    }

    @Test
    void anUnknownDeviceMustSendAUsableKeyAndPlatformWhileAKnownDeviceReusesItsStoredKey() {
        assertThat(initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, null, null)))
                .isInstanceOf(InitEnrollmentResult.DeviceKeyRequired.class);
        when(challenges.sealChallenge(eq("bad"), any(), any())).thenThrow(new InvalidEncryptionKeyException("not P-256"));
        assertThat(initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, "bad", DevicePlatform.IOS)))
                .isInstanceOf(InitEnrollmentResult.DeviceKeyRequired.class);
        assertThat(transactions.rows).isEmpty();

        // The tablet is known with a stored key: init without a key challenges that key and targets its row.
        TrustedDevice knownTablet = DomainFixtures.trustedDevice(new DeviceInstallation(ALICE, Channel.MOBILE, TABLET),
                DevicePlatform.IOS, "{stored-key}", NOW.minusSeconds(60));
        devices.rows.put(knownTablet.id(), knownTablet);
        when(challenges.sealChallenge(eq("{stored-key}"), eq(ENROLLMENT), eq(CHALLENGE))).thenReturn("jwe.stored");
        InitEnrollmentResult result = initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, null, null));
        assertThat(((InitEnrollmentResult.KeyExchange) result).challenge()).isEqualTo("jwe.stored");
        assertThat(payload(transactions).targetDeviceId()).isEqualTo(knownTablet.id());
        assertThat(payload(transactions).devicePublicJwk()).isEqualTo("{stored-key}");
    }

    @Test
    void verifyCountsTheAttemptOpensTheMfaTransactionOnlyAfterTheKeyIsProven() {
        initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS));

        VerifyEnrollmentResult wrong = verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.garbage"));
        assertThat(wrong).isEqualTo(new VerifyEnrollmentResult.WrongChallenge(2));
        verifyNoInteractions(mfa);
        assertThat(payload(transactions).verifyAttempts()).isEqualTo(1);

        VerifyEnrollmentResult ok = verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer"));
        assertThat(ok).isEqualTo(new VerifyEnrollmentResult.MfaRequired("mfa-1", NOW.plus(Duration.ofMinutes(5))));
        assertThat(payload(transactions).state()).isEqualTo(EnrollmentState.MFA_REQUIRED);
        assertThat(payload(transactions).mfaTransactionId()).isEqualTo("mfa-1");
        var request = org.mockito.ArgumentCaptor.forClass(MfaTransactionRequest.class);
        verify(mfa).create(request.capture());
        assertThat(request.getValue().customerId()).isEqualTo(ALICE);
        assertThat(request.getValue().authOperationId()).isEqualTo(ENROLLMENT);
        assertThat(request.getValue().purpose()).isEqualTo(EnrollmentPurpose.TRUST_DEVICE);
        assertThat(request.getValue().notAfter()).isEqualTo(NOW.plus(ENROLLMENT_LIFETIME));
        assertThat(request.getValue().contextDigest()).isEqualTo(EnrollmentDigests.contextDigest(payload(transactions)));

        assertThat(verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer")))
                .isInstanceOf(VerifyEnrollmentResult.Conflict.class); // verify runs once
    }

    @Test
    void theThirdWrongAnswerEndsTheTransactionAndTheRestrictedSession() {
        initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS));
        assertThat(verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "x"))).isEqualTo(new VerifyEnrollmentResult.WrongChallenge(2));
        assertThat(verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "x"))).isEqualTo(new VerifyEnrollmentResult.WrongChallenge(1));
        assertThat(verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "x"))).isEqualTo(new VerifyEnrollmentResult.WrongChallenge(0));
        assertThat(transactions.rows).isEmpty();
        assertThat(sessions.findByToken(RESTRICTED)).isEmpty();
        assertThat(verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer")))
                .isInstanceOf(VerifyEnrollmentResult.Conflict.class);
    }

    @Test
    void noUsableFactorEndsEverythingAndAnMfaOutageChangesNothing() {
        initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS));
        doThrow(new PartnerUnavailableException("MFA")).when(mfa).create(any());
        assertThat(verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer")))
                .isInstanceOf(VerifyEnrollmentResult.Unavailable.class);
        assertThat(payload(transactions).state()).isEqualTo(EnrollmentState.KEY_EXCHANGE); // the attempt is counted, nothing else
        assertThat(payload(transactions).verifyAttempts()).isEqualTo(1);

        doReturn(new CreateResult.NoUsableFactor()).when(mfa).create(any());
        assertThat(verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer")))
                .isInstanceOf(VerifyEnrollmentResult.NoUsableFactor.class);
        assertThat(transactions.rows).isEmpty();
        assertThat(sessions.findByToken(RESTRICTED)).isEmpty();
    }

    @Test
    void confirmPassedCommitsTrustWritesTheEnrollmentRowOnceAndIssuesAnActiveSession() {
        initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS));
        verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer"));
        when(mfa.check(argThat(check -> check.mfaTransactionId().equals("mfa-1") && check.authOperationId().equals(ENROLLMENT)
                && check.customerId().equals(ALICE)))).thenReturn(new CheckResult.Passed("receipt-sha"));

        ConfirmEnrollmentResult result = confirmEnrollment.confirm(new ConfirmEnrollmentCommand(TABLET_SESSION, "{app-kenc}"));

        assertThat(result).isInstanceOf(ConfirmEnrollmentResult.Trusted.class);
        ConfirmEnrollmentResult.Trusted trusted = (ConfirmEnrollmentResult.Trusted) result;
        assertThat(trusted.tokenEnvelope()).isEqualTo("jwe.token");
        assertThat(trusted.idleExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(transactions.rows).isEmpty();
        assertThat(sessions.findByToken(RESTRICTED)).isEmpty();
        Session active = sessions.findByToken(NEW_TOKEN).orElseThrow().session();
        assertThat(active.status()).isEqualTo(SessionStatus.ACTIVE);
        assertThat(active.deviceId()).isEqualTo(TABLET);

        TrustConfirmation confirmation = devices.confirmations.getFirst();
        assertThat(confirmation.enrollment().id()).isEqualTo(ENROLLMENT);
        assertThat(confirmation.enrollment().state()).isEqualTo(EnrollmentState.COMPLETED);
        assertThat(confirmation.enrollment().purpose()).isEqualTo(EnrollmentPurpose.TRUST_DEVICE);
        assertThat(confirmation.enrollment().verifyAttempts()).isEqualTo(1);
        assertThat(confirmation.creationSessionId()).isEqualTo(TABLET_SESSION.sessionId()); // the row is new at this commit
        assertThat(confirmation.receiptDigest()).isEqualTo("receipt-sha");
        assertThat(confirmation.replaced()).isNull();
        TrustedDevice tablet = devices.findLive(ALICE, Channel.MOBILE, TABLET).orElseThrow();
        assertThat(tablet.publicKey()).isEqualTo(DEVICE_KEY);
        assertThat(tablet.platform()).isEqualTo(DevicePlatform.IOS);
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).contains(tablet.id());
        assertThat(devices.findLive(ALICE, Channel.MOBILE, PHONE)).isPresent(); // the old primary stays trusted

        assertThat(confirmEnrollment.confirm(new ConfirmEnrollmentCommand(TABLET_SESSION, "{app-kenc}")))
                .isInstanceOf(ConfirmEnrollmentResult.Conflict.class);
        assertThat(devices.confirmations).hasSize(1);
    }

    @Test
    void ofTwoConfirmsThatBothSawThePassedMfaOnlyOneCommits() {
        initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS));
        verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer"));
        // The racing confirm removes the transaction while this one waits for MFA.
        when(mfa.check(any())).thenAnswer(invocation -> {
            transactions.rows.clear();
            return new CheckResult.Passed("receipt");
        });

        assertThat(confirmEnrollment.confirm(new ConfirmEnrollmentCommand(TABLET_SESSION, "{app-kenc}")))
                .isInstanceOf(ConfirmEnrollmentResult.Conflict.class);
        assertThat(devices.confirmations).isEmpty();
        assertThat(sessions.findByToken(RESTRICTED)).isPresent();
        verify(tokens, never()).next(any(), any());
    }

    @Test
    void aRestrictedSessionThatIsAlreadyGoneCommitsNothing() {
        initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS));
        verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer"));
        when(mfa.check(any())).thenReturn(new CheckResult.Passed("receipt"));
        sessions.rows.clear(); // logged out after the BFF admitted the confirm

        assertThat(confirmEnrollment.confirm(new ConfirmEnrollmentCommand(TABLET_SESSION, "{app-kenc}")))
                .isInstanceOf(ConfirmEnrollmentResult.Conflict.class);
        assertThat(devices.confirmations).isEmpty();
        assertThat(transactions.rows).isEmpty();
    }

    @Test
    void aReinstallReplacesTheOldRowOfTheSameInstallation() {
        TrustedDevice oldTablet = DomainFixtures.trustedDevice(new DeviceInstallation(ALICE, Channel.MOBILE, TABLET),
                DevicePlatform.IOS, "{old-key}", NOW.minusSeconds(60));
        devices.rows.put(oldTablet.id(), oldTablet);
        initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS)); // a new key: reinstall
        verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer"));
        when(mfa.check(any())).thenReturn(new CheckResult.Passed("r"));

        confirmEnrollment.confirm(new ConfirmEnrollmentCommand(TABLET_SESSION, "{app-kenc}"));

        assertThat(devices.rows.get(oldTablet.id()).status()).isEqualTo(DeviceStatus.EXPIRED);
        assertThat(devices.findLive(ALICE, Channel.MOBILE, TABLET).orElseThrow().publicKey()).isEqualTo(DEVICE_KEY);
        assertThat(devices.confirmations.getFirst().replaced().id()).isEqualTo(oldTablet.id());
    }

    @Test
    void confirmMapsPendingRejectedOutageAndExpired() {
        initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS));
        verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer"));

        when(mfa.check(any())).thenReturn(new CheckResult.Pending());
        assertThat(confirmEnrollment.confirm(new ConfirmEnrollmentCommand(TABLET_SESSION, "{app-kenc}"))).isInstanceOf(ConfirmEnrollmentResult.MfaPending.class);
        when(mfa.check(any())).thenReturn(new CheckResult.Rejected());
        assertThat(confirmEnrollment.confirm(new ConfirmEnrollmentCommand(TABLET_SESSION, "{app-kenc}"))).isInstanceOf(ConfirmEnrollmentResult.Rejected.class);
        doThrow(new PartnerUnavailableException("MFA")).when(mfa).check(any());
        assertThat(confirmEnrollment.confirm(new ConfirmEnrollmentCommand(TABLET_SESSION, "{app-kenc}"))).isInstanceOf(ConfirmEnrollmentResult.Unavailable.class);
        assertThat(sessions.findByToken(RESTRICTED)).isPresent();
        assertThat(payload(transactions).state()).isEqualTo(EnrollmentState.MFA_REQUIRED);
        verify(tokens, never()).next(any(), any());

        doReturn(new CheckResult.Expired()).when(mfa).check(any());
        assertThat(confirmEnrollment.confirm(new ConfirmEnrollmentCommand(TABLET_SESSION, "{app-kenc}"))).isInstanceOf(ConfirmEnrollmentResult.MfaExpired.class);
        assertThat(transactions.rows).isEmpty();
        assertThat(sessions.findByToken(RESTRICTED)).isEmpty();
        assertThat(devices.findLive(ALICE, Channel.MOBILE, TABLET)).isEmpty();
        assertThat(devices.confirmations).isEmpty();
    }

    @Test
    void aFailedMfaEndsTheTransactionAndTheSession() {
        initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS));
        verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer"));
        when(mfa.check(any())).thenReturn(new CheckResult.Failed());

        assertThat(confirmEnrollment.confirm(new ConfirmEnrollmentCommand(TABLET_SESSION, "{app-kenc}"))).isInstanceOf(ConfirmEnrollmentResult.MfaFailed.class);
        assertThat(transactions.rows).isEmpty();
        assertThat(sessions.findByToken(RESTRICTED)).isEmpty();
        assertThat(devices.confirmations).isEmpty();
    }

    @Test
    void aTransactionPastItsDeadlineCannotBeContinued() {
        initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS));
        Clock later = Clock.fixed(NOW.plus(ENROLLMENT_LIFETIME), ZoneOffset.UTC);
        VerifyEnrollmentService laterVerify = new VerifyEnrollmentService(sessionService,
                new EnrollmentTransactions(transactions, ENROLLMENT_LIFETIME, later), challenges, mfa,
                EnrollmentPolicy.standard());

        assertThat(laterVerify.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer")))
                .isInstanceOf(VerifyEnrollmentResult.Conflict.class);
        verifyNoInteractions(mfa);
    }

    @Test
    void confirmBeforeVerifyAndAnActiveSessionAreConflicts() {
        initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS));
        assertThat(confirmEnrollment.confirm(new ConfirmEnrollmentCommand(TABLET_SESSION, "{app-kenc}"))).isInstanceOf(ConfirmEnrollmentResult.Conflict.class);
        verifyNoInteractions(mfa);

        // The BFF admitted an ACTIVE session: the route is for restricted ones, so nothing is read or written.
        AdmittedSession activePhone = new AdmittedSession(SessionId.random(), ALICE, Channel.MOBILE, PHONE, SessionStatus.ACTIVE);
        assertThat(initEnrollment.init(new InitEnrollmentCommand(activePhone, DEVICE_KEY, DevicePlatform.ANDROID)))
                .isInstanceOf(InitEnrollmentResult.Conflict.class);
        assertThat(verifyEnrollment.verify(new VerifyEnrollmentCommand(activePhone, "jwe.answer")))
                .isInstanceOf(VerifyEnrollmentResult.Conflict.class);
        assertThat(confirmEnrollment.confirm(new ConfirmEnrollmentCommand(activePhone, "{app-kenc}")))
                .isInstanceOf(ConfirmEnrollmentResult.Conflict.class);
        assertThat(transactions.rows).hasSize(1);
    }

    @Test
    void aCacheOutageIsUnavailableAndWritesNothing() {
        transactions.unavailable = true;

        assertThat(initEnrollment.init(new InitEnrollmentCommand(TABLET_SESSION, DEVICE_KEY, DevicePlatform.IOS)))
                .isInstanceOf(InitEnrollmentResult.Unavailable.class);
        assertThat(verifyEnrollment.verify(new VerifyEnrollmentCommand(TABLET_SESSION, "jwe.answer")))
                .isInstanceOf(VerifyEnrollmentResult.Unavailable.class);
        assertThat(confirmEnrollment.confirm(new ConfirmEnrollmentCommand(TABLET_SESSION, "{app-kenc}")))
                .isInstanceOf(ConfirmEnrollmentResult.Unavailable.class);
        assertThat(sessions.findByToken(RESTRICTED)).isPresent();
        verifyNoInteractions(mfa);
    }

    private static EnrollmentTransaction payload(InMemoryTransactionStore store) {
        CacheTransaction<EnrollmentTransaction> transaction = store.only();
        return transaction.payload();
    }
}
