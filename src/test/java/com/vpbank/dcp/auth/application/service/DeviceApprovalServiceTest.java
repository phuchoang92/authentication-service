package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.auth.application.command.ApprovalStatusCommand;
import com.vpbank.dcp.auth.application.command.ApproveEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.AuthorizeEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.ClaimEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.ListPendingDevicesCommand;
import com.vpbank.dcp.auth.application.command.RequestApprovalCommand;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.AuthorizationTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CheckResult;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CreateResult;
import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import com.vpbank.dcp.auth.application.port.out.model.TrustConfirmation;
import com.vpbank.dcp.auth.application.result.ApprovalStatusResult;
import com.vpbank.dcp.auth.application.result.ApproveEnrollmentResult;
import com.vpbank.dcp.auth.application.result.AuthorizeEnrollmentResult;
import com.vpbank.dcp.auth.application.result.ClaimEnrollmentResult;
import com.vpbank.dcp.auth.application.result.ListPendingDevicesResult;
import com.vpbank.dcp.auth.application.result.RequestApprovalResult;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.MfaFactor;
import com.vpbank.dcp.auth.domain.enums.PrimaryMode;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.enums.TrustLevel;
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
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Alice has a trusted primary phone (ACTIVE session) and a trusted tablet that is not primary. A new watch logs
 * in and gets a restricted session; the phone approves it with FACE + OTP and shows the QR; the watch claims it.
 */
class DeviceApprovalServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00Z");
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final DeviceId PHONE = new DeviceId("phone-1");
    private static final DeviceId TABLET = new DeviceId("tablet-2");
    private static final DeviceId WATCH = new DeviceId("watch-3");
    private static final OpaqueToken PHONE_TOKEN = new OpaqueToken("k1." + "A".repeat(43));
    private static final OpaqueToken TABLET_TOKEN = new OpaqueToken("k1." + "T".repeat(43));
    private static final OpaqueToken WATCH_TOKEN = new OpaqueToken("k1." + "B".repeat(43));
    private static final OpaqueToken NEW_TOKEN = new OpaqueToken("k1." + "C".repeat(43));
    private static final EnrollmentId ENROLLMENT = EnrollmentId.random();
    private static final String WATCH_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"watch\"}";
    private static final String QR_TOKEN = "q".repeat(43);

    private final InMemorySessionStore sessions = new InMemorySessionStore();
    private final InMemoryEnrollmentRepository enrollments = new InMemoryEnrollmentRepository();
    private final InMemoryTrustedDeviceRepository devices = new InMemoryTrustedDeviceRepository();
    private final MfaTransactionPort mfa = mock(MfaTransactionPort.class);
    private final AuthorizationTokenGenerator qrTokens = mock(AuthorizationTokenGenerator.class);
    private final TokenEnvelopeSealer sealer = mock(TokenEnvelopeSealer.class);
    private final OpaqueTokenGenerator tokens = mock(OpaqueTokenGenerator.class);
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final TrustedDeviceService trustedDevices = new TrustedDeviceService(devices, DevicePolicy.standard(),
            TrustedDeviceId::random, clock);
    private final DeviceApprovalService service = new DeviceApprovalService(sessions, enrollments, devices, trustedDevices,
            mfa, qrTokens, sealer, tokens, () -> ENROLLMENT, SessionId::random, EnrollmentPolicy.standard(),
            new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20), Duration.ofSeconds(30)), clock);

    private TrustedDevice phone;

    @BeforeEach
    void aliceHasAPrimaryPhoneATrustedTabletAndAWatchOnARestrictedSession() {
        phone = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, PHONE, DevicePlatform.ANDROID,
                "{phone-key}", NOW.minusSeconds(3600), DevicePolicy.standard());
        TrustedDevice tablet = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, TABLET,
                DevicePlatform.IOS, "{tablet-key}", NOW.minusSeconds(1800), DevicePolicy.standard());
        devices.rows.put(phone.id(), phone);
        devices.rows.put(tablet.id(), tablet);
        devices.primaries.put(new InMemoryTrustedDeviceRepository.Key(ALICE, Channel.MOBILE), phone.id());
        sessions.create(Session.start(SessionId.random(), ALICE, PHONE, Channel.MOBILE, NOW, sessionPolicy()), PHONE_TOKEN);
        sessions.create(Session.start(SessionId.random(), ALICE, TABLET, Channel.MOBILE, NOW, sessionPolicy()), TABLET_TOKEN);
        sessions.create(Session.startRestricted(SessionId.random(), ALICE, WATCH, Channel.MOBILE, NOW, DevicePolicy.standard()),
                WATCH_TOKEN);
        when(mfa.create(any())).thenReturn(new CreateResult.Created("mfa-7", NOW.plus(Duration.ofMinutes(5))));
        when(qrTokens.next()).thenReturn(QR_TOKEN);
        when(tokens.next()).thenReturn(NEW_TOKEN);
        when(sealer.seal(eq("{watch-kenc}"), eq(NEW_TOKEN), any())).thenReturn("jwe.token");
    }

    @Test
    void theWatchRequestsApprovalAndGetsAPendingRowThatIsNotTrusted() {
        RequestApprovalResult result = service.request(new RequestApprovalCommand(WATCH_TOKEN, WATCH_KEY, DevicePlatform.IOS));

        assertThat(result).isInstanceOf(RequestApprovalResult.WaitingApproval.class);
        RequestApprovalResult.WaitingApproval waiting = (RequestApprovalResult.WaitingApproval) result;
        assertThat(waiting.enrollmentId()).isEqualTo(ENROLLMENT);
        assertThat(waiting.expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(10)));
        DeviceEnrollment stored = enrollments.only();
        assertThat(stored.purpose()).isEqualTo(EnrollmentPurpose.TRUST_DEVICE_APPROVAL);
        assertThat(stored.state()).isEqualTo(EnrollmentState.WAITING_APPROVAL);
        TrustedDevice watchRow = devices.findLive(ALICE, Channel.MOBILE, WATCH).orElseThrow();
        assertThat(watchRow.isPending()).isTrue();
        assertThat(watchRow.publicKey()).isEqualTo(WATCH_KEY);
        assertThat(stored.targetDeviceId()).isEqualTo(watchRow.id());
        assertThat(devices.audit).contains(stored.id() == null ? "" : sessions.findByToken(WATCH_TOKEN).orElseThrow()
                .session().id() + ":DEVICE_REGISTERED");

        // The same session asking again gets the same request; the status poll says it waits.
        assertThat(service.request(new RequestApprovalCommand(WATCH_TOKEN, null, null)))
                .isEqualTo(new RequestApprovalResult.WaitingApproval(ENROLLMENT, stored.expiresAt()));
        assertThat(enrollments.rows).hasSize(1);
        assertThat(service.status(new ApprovalStatusCommand(WATCH_TOKEN)))
                .isEqualTo(new ApprovalStatusResult.Status(ENROLLMENT, EnrollmentState.WAITING_APPROVAL, stored.expiresAt()));
    }

    @Test
    void anUnknownDeviceMustSendItsKeyAndTheQuotaAndSessionKindAreEnforced() {
        assertThat(service.request(new RequestApprovalCommand(WATCH_TOKEN, null, DevicePlatform.IOS)))
                .isInstanceOf(RequestApprovalResult.DeviceKeyRequired.class);
        assertThat(service.request(new RequestApprovalCommand(PHONE_TOKEN, WATCH_KEY, DevicePlatform.IOS)))
                .isInstanceOf(RequestApprovalResult.SessionGone.class); // an ACTIVE session is not a restricted one
        assertThat(service.status(new ApprovalStatusCommand(WATCH_TOKEN))).isInstanceOf(ApprovalStatusResult.NoRequest.class);

        // Three installations already wait: the fourth is refused before any row is written.
        for (int i = 0; i < 3; i++) {
            TrustedDevice waiting = TrustedDevice.pending(TrustedDeviceId.random(), ALICE, Channel.MOBILE,
                    new DeviceId("other-" + i), DevicePlatform.IOS, "{k}", NOW, Duration.ofMinutes(10));
            devices.rows.put(waiting.id(), waiting);
        }
        assertThat(service.request(new RequestApprovalCommand(WATCH_TOKEN, WATCH_KEY, DevicePlatform.IOS)))
                .isInstanceOf(RequestApprovalResult.TooManyPending.class);
        assertThat(enrollments.rows).isEmpty();
        assertThat(devices.findLive(ALICE, Channel.MOBILE, WATCH)).isEmpty();
    }

    @Test
    void onlyThePrimaryDeviceSeesAndApprovesTheRequestWithFaceAndOtp() {
        service.request(new RequestApprovalCommand(WATCH_TOKEN, WATCH_KEY, DevicePlatform.IOS));

        assertThat(service.pending(new ListPendingDevicesCommand(TABLET_TOKEN)))
                .isInstanceOf(ListPendingDevicesResult.NotPrimaryDevice.class);
        assertThat(service.pending(new ListPendingDevicesCommand(WATCH_TOKEN)))
                .isInstanceOf(ListPendingDevicesResult.SessionGone.class); // restricted sessions never list
        assertThat(service.approve(new ApproveEnrollmentCommand(TABLET_TOKEN, ENROLLMENT)))
                .isInstanceOf(ApproveEnrollmentResult.NotPrimaryDevice.class);
        verifyNoInteractions(mfa);

        ListPendingDevicesResult listed = service.pending(new ListPendingDevicesCommand(PHONE_TOKEN));
        assertThat(listed).isInstanceOf(ListPendingDevicesResult.Pending.class);
        List<com.vpbank.dcp.auth.application.result.PendingDeviceSummary> pendingDevices =
                ((ListPendingDevicesResult.Pending) listed).devices();
        assertThat(pendingDevices).hasSize(1);
        assertThat(pendingDevices.get(0).enrollmentId()).isEqualTo(ENROLLMENT);
        assertThat(pendingDevices.get(0).deviceId()).isEqualTo(WATCH);
        assertThat(pendingDevices.get(0).platform()).isEqualTo(DevicePlatform.IOS);

        ApproveEnrollmentResult approved = service.approve(new ApproveEnrollmentCommand(PHONE_TOKEN, ENROLLMENT));
        assertThat(approved).isEqualTo(new ApproveEnrollmentResult.MfaRequired("mfa-7", NOW.plus(Duration.ofMinutes(5))));
        verify(mfa).create(argThat((MfaTransactionRequest request) -> request.purpose() == EnrollmentPurpose.TRUST_DEVICE_APPROVAL
                && request.factors().equals(List.of(MfaFactor.FACE, MfaFactor.OTP))
                && request.authOperationId().equals(ENROLLMENT)));
        DeviceEnrollment stored = enrollments.only();
        assertThat(stored.actorDeviceId()).isEqualTo(phone.id());
        assertThat(stored.mfaTransactionId()).isEqualTo("mfa-7");

        // Approving twice, or claiming before the token exists, is a conflict.
        assertThat(service.approve(new ApproveEnrollmentCommand(PHONE_TOKEN, ENROLLMENT)))
                .isInstanceOf(ApproveEnrollmentResult.Conflict.class);
        assertThat(service.claim(new ClaimEnrollmentCommand(WATCH_TOKEN, QR_TOKEN, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.Conflict.class);
    }

    @Test
    void theTokenIsIssuedOnlyAfterMfaPassedAndOnlyToTheApprovingDevice() {
        service.request(new RequestApprovalCommand(WATCH_TOKEN, WATCH_KEY, DevicePlatform.IOS));
        assertThat(service.authorize(new AuthorizeEnrollmentCommand(PHONE_TOKEN, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.Conflict.class); // not approved yet
        service.approve(new ApproveEnrollmentCommand(PHONE_TOKEN, ENROLLMENT));

        when(mfa.check(any())).thenReturn(new CheckResult.Pending());
        assertThat(service.authorize(new AuthorizeEnrollmentCommand(PHONE_TOKEN, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.MfaPending.class);
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.WAITING_APPROVAL);

        doReturn(new CheckResult.Passed("receipt")).when(mfa).check(argThat(check ->
                check.mfaTransactionId().equals("mfa-7") && check.factorClaim().equals("FACE+OTP")
                        && check.purpose() == EnrollmentPurpose.TRUST_DEVICE_APPROVAL));
        AuthorizeEnrollmentResult authorized = service.authorize(new AuthorizeEnrollmentCommand(PHONE_TOKEN, ENROLLMENT));
        assertThat(authorized).isEqualTo(new AuthorizeEnrollmentResult.Authorized(ENROLLMENT, QR_TOKEN, NOW.plusSeconds(180)));
        DeviceEnrollment stored = enrollments.only();
        assertThat(stored.state()).isEqualTo(EnrollmentState.WAITING_AUTHORIZATION);
        assertThat(stored.authorizationTokenDigest()).isNotEqualTo(QR_TOKEN).hasSize(43);
        assertThat(stored.mfaMethod()).isEqualTo("FACE+OTP");
        assertThat(service.status(new ApprovalStatusCommand(WATCH_TOKEN)))
                .isEqualTo(new ApprovalStatusResult.Status(ENROLLMENT, EnrollmentState.WAITING_AUTHORIZATION, stored.expiresAt()));

        // A second authorize finds no approval in progress any more.
        assertThat(service.authorize(new AuthorizeEnrollmentCommand(PHONE_TOKEN, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.Conflict.class);
    }

    @Test
    void mfaFailureOrExpiryEndsTheRequestAndAnMfaOutageChangesNothing() {
        service.request(new RequestApprovalCommand(WATCH_TOKEN, WATCH_KEY, DevicePlatform.IOS));
        service.approve(new ApproveEnrollmentCommand(PHONE_TOKEN, ENROLLMENT));
        doReturn(new CheckResult.Failed()).when(mfa).check(any());
        assertThat(service.authorize(new AuthorizeEnrollmentCommand(PHONE_TOKEN, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.MfaFailed.class);
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.FAILED);
        assertThat(service.status(new ApprovalStatusCommand(WATCH_TOKEN)))
                .isEqualTo(new ApprovalStatusResult.Status(ENROLLMENT, EnrollmentState.FAILED, enrollments.only().expiresAt()));

        enrollments.rows.clear();
        enrollments.bySession.clear();
        service.request(new RequestApprovalCommand(WATCH_TOKEN, WATCH_KEY, DevicePlatform.IOS));
        service.approve(new ApproveEnrollmentCommand(PHONE_TOKEN, ENROLLMENT));
        doReturn(new CheckResult.Rejected()).when(mfa).check(any());
        assertThat(service.authorize(new AuthorizeEnrollmentCommand(PHONE_TOKEN, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.Rejected.class);
        org.mockito.Mockito.doThrow(new PartnerUnavailableException("MFA")).when(mfa).check(any());
        assertThat(service.authorize(new AuthorizeEnrollmentCommand(PHONE_TOKEN, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.Unavailable.class);
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.WAITING_APPROVAL);
        assertThat(enrollments.only().hasApprovalInProgress()).isTrue();
    }

    @Test
    void theClaimMakesTheWatchTrustedAndPrimaryAndOpensAnActiveSessionWhileThePhoneStaysTrusted() {
        authorizeTheWatch();

        ClaimEnrollmentResult result = service.claim(new ClaimEnrollmentCommand(WATCH_TOKEN, QR_TOKEN, "{watch-kenc}"));

        assertThat(result).isInstanceOf(ClaimEnrollmentResult.Trusted.class);
        ClaimEnrollmentResult.Trusted trusted = (ClaimEnrollmentResult.Trusted) result;
        assertThat(trusted.tokenEnvelope()).isEqualTo("jwe.token");
        assertThat(trusted.idleExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));

        TrustedDevice watch = devices.findLive(ALICE, Channel.MOBILE, WATCH).orElseThrow();
        assertThat(watch.status()).isEqualTo(DeviceStatus.ACTIVE);
        assertThat(watch.trustLevel()).isEqualTo(TrustLevel.TRUSTED);
        assertThat(watch.isTrusted(NOW)).isTrue();
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).contains(watch.id());
        assertThat(devices.findLive(ALICE, Channel.MOBILE, PHONE).orElseThrow().isTrusted(NOW)).isTrue();
        TrustConfirmation confirmation = devices.confirmations.get(0);
        assertThat(confirmation.primaryMode()).isEqualTo(PrimaryMode.OLD_DEVICE_APPROVAL);
        assertThat(confirmation.faceAuthenticated()).isFalse();
        assertThat(confirmation.actorDeviceId()).isEqualTo(phone.id());
        assertThat(confirmation.replaced()).isNull();
        assertThat(confirmation.enrollment().state()).isEqualTo(EnrollmentState.COMPLETED);
        assertThat(confirmation.enrollment().authorizationConsumedAt()).isEqualTo(NOW);

        // The restricted session is gone; the new ACTIVE session belongs to the watch.
        assertThat(sessions.findByToken(WATCH_TOKEN)).isEmpty();
        Session active = sessions.findByToken(NEW_TOKEN).orElseThrow().session();
        assertThat(active.status()).isEqualTo(SessionStatus.ACTIVE);
        assertThat(active.deviceId()).isEqualTo(WATCH);
        assertThat(service.claim(new ClaimEnrollmentCommand(WATCH_TOKEN, QR_TOKEN, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.SessionGone.class);
    }

    @Test
    void wrongTokensAreCountedBeforeTheCheckAndTheFifthOneEndsTheRequestAndTheSession() {
        authorizeTheWatch();

        for (int attemptsLeft = 4; attemptsLeft >= 1; attemptsLeft--) {
            assertThat(service.claim(new ClaimEnrollmentCommand(WATCH_TOKEN, "wrong", "{watch-kenc}")))
                    .isEqualTo(new ClaimEnrollmentResult.WrongAuthorization(attemptsLeft));
        }
        assertThat(enrollments.only().authorizationAttempts()).isEqualTo(4);
        assertThat(service.claim(new ClaimEnrollmentCommand(WATCH_TOKEN, "wrong", "{watch-kenc}")))
                .isEqualTo(new ClaimEnrollmentResult.WrongAuthorization(0));
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.FAILED);
        assertThat(sessions.findByToken(WATCH_TOKEN)).isEmpty();
        assertThat(devices.findLive(ALICE, Channel.MOBILE, WATCH).orElseThrow().isPending()).isTrue();
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).contains(phone.id());
    }

    @Test
    void anExpiredTokenEndsTheRequestAndTheSessionAndAClaimFromAnotherSessionIsAConflict() {
        authorizeTheWatch();
        // Another restricted session of the same watch (a second login) did not make the request.
        OpaqueToken otherWatchToken = new OpaqueToken("k1." + "D".repeat(43));
        sessions.create(Session.startRestricted(SessionId.random(), ALICE, WATCH, Channel.MOBILE, NOW, DevicePolicy.standard()),
                otherWatchToken);
        assertThat(service.claim(new ClaimEnrollmentCommand(otherWatchToken, QR_TOKEN, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.Conflict.class);

        Clock later = Clock.fixed(NOW.plusSeconds(180), ZoneOffset.UTC);
        DeviceApprovalService laterService = new DeviceApprovalService(sessions, enrollments, devices, trustedDevices, mfa,
                qrTokens, sealer, tokens, () -> ENROLLMENT, SessionId::random, EnrollmentPolicy.standard(),
                sessionPolicy(), later);
        assertThat(laterService.claim(new ClaimEnrollmentCommand(WATCH_TOKEN, QR_TOKEN, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.AuthorizationExpired.class);
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.EXPIRED);
        assertThat(sessions.findByToken(WATCH_TOKEN)).isEmpty();
    }

    @Test
    void theOldestDeviceExpiresWhenTheApprovedOneWouldExceedTheCap() {
        for (int i = 0; i < 3; i++) {
            TrustedDevice extra = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE,
                    new DeviceId("extra-" + i), DevicePlatform.IOS, "{k}", NOW.minusSeconds(7200 + i), DevicePolicy.standard());
            devices.rows.put(extra.id(), extra);
        }
        authorizeTheWatch(); // phone, tablet, 3 extras and the pending watch: 6 live rows

        service.claim(new ClaimEnrollmentCommand(WATCH_TOKEN, QR_TOKEN, "{watch-kenc}"));

        TrustConfirmation confirmation = devices.confirmations.get(0);
        assertThat(confirmation.expiredByCap()).hasSize(1);
        assertThat(confirmation.expiredByCap().get(0).deviceId()).isEqualTo(new DeviceId("extra-2")); // oldest login
        assertThat(devices.findLive(ALICE, Channel.MOBILE)).hasSize(5);
    }

    private void authorizeTheWatch() {
        service.request(new RequestApprovalCommand(WATCH_TOKEN, WATCH_KEY, DevicePlatform.IOS));
        service.approve(new ApproveEnrollmentCommand(PHONE_TOKEN, ENROLLMENT));
        when(mfa.check(any())).thenReturn(new CheckResult.Passed("receipt"));
        assertThat(service.authorize(new AuthorizeEnrollmentCommand(PHONE_TOKEN, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.Authorized.class);
    }

    private static SessionPolicy sessionPolicy() {
        return new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20), Duration.ofSeconds(30));
    }
}
