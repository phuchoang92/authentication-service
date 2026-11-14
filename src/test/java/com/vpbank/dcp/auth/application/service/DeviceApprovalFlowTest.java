package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.domain.model.DeviceInstallation;
import com.vpbank.dcp.auth.domain.model.DomainFixtures;
import com.vpbank.dcp.auth.domain.model.NewSession;
import com.vpbank.dcp.auth.domain.model.DeviceKey;
import com.vpbank.dcp.auth.domain.model.KeyExchangeStart;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CheckResult;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CreateResult;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
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
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
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
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Alice has a trusted primary phone (ACTIVE session) and a trusted tablet that is not primary. A new watch logs
 * in and gets a restricted session; the phone approves it with FACE + OTP and shows the QR; the watch claims it.
 */
class DeviceApprovalFlowTest {
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00Z");
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final DeviceId PHONE = new DeviceId("phone-1");
    private static final DeviceId TABLET = new DeviceId("tablet-2");
    private static final DeviceId WATCH = new DeviceId("watch-3");
    private static final OpaqueToken PHONE_TOKEN = new OpaqueToken("s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000001:" + "A".repeat(43));
    private static final OpaqueToken TABLET_TOKEN = new OpaqueToken("s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000020:" + "T".repeat(43));
    private static final OpaqueToken WATCH_TOKEN = new OpaqueToken("s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000002:" + "B".repeat(43));
    // The same sessions as the BFF admits them (slice 11): each with the session ID of its token above.
    private static final AdmittedSession PHONE_SESSION = new AdmittedSession(PHONE_TOKEN.sessionId(), ALICE,
            Channel.MOBILE, PHONE, SessionStatus.ACTIVE);
    private static final AdmittedSession TABLET_SESSION = new AdmittedSession(TABLET_TOKEN.sessionId(), ALICE,
            Channel.MOBILE, TABLET, SessionStatus.ACTIVE);
    private static final AdmittedSession WATCH_SESSION = new AdmittedSession(WATCH_TOKEN.sessionId(), ALICE,
            Channel.MOBILE, WATCH, SessionStatus.NEED_TRUSTED_DEVICE);
    private static final OpaqueToken NEW_TOKEN = new OpaqueToken("s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000003:" + "C".repeat(43));
    private static final EnrollmentId ENROLLMENT = EnrollmentId.random();
    private static final String WATCH_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"watch\"}";
    private static final String QR_TOKEN = "q".repeat(43);

    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final InMemorySessionStore sessions = new InMemorySessionStore();
    private final InMemoryEnrollmentRepository enrollments = new InMemoryEnrollmentRepository(clock);
    private final InMemoryTransactionStore transactions = new InMemoryTransactionStore();
    private final InMemoryTrustedDeviceRepository devices = new InMemoryTrustedDeviceRepository();
    private final MfaTransactionPort mfa = mock(MfaTransactionPort.class);
    private final AuthorizationTokenGenerator qrTokens = mock(AuthorizationTokenGenerator.class);
    private final TokenEnvelopeSealer sealer = mock(TokenEnvelopeSealer.class);
    private final OpaqueTokenGenerator tokens = mock(OpaqueTokenGenerator.class);
    private final EnrollmentTransactions enrollmentTransactions =
            new EnrollmentTransactions(transactions, Duration.ofMinutes(10), clock);
    private final TrustedDeviceService trustedDevices = new TrustedDeviceService(devices, DevicePolicy.standard(),
            TrustedDeviceId::random, clock);
    private final SessionService sessionService = new SessionService(sessions, sealer, tokens, SessionId::random,
            sessionPolicy(), DevicePolicy.standard(), clock);
    private final ApprovalRequests approvalRequests = new ApprovalRequests(enrollments, clock);
    private final RequestApprovalService requestApproval = new RequestApprovalService(approvalRequests,
            enrollmentTransactions, trustedDevices, () -> ENROLLMENT, EnrollmentPolicy.standard(), clock);
    private final ApprovalStatusService approvalStatus = new ApprovalStatusService(approvalRequests, clock);
    private final ListPendingDevicesService listPendingDevices = new ListPendingDevicesService(trustedDevices,
            approvalRequests);
    private final ApproveEnrollmentService approveEnrollment = new ApproveEnrollmentService(trustedDevices,
            approvalRequests, mfa);
    private final AuthorizeEnrollmentService authorizeEnrollment = new AuthorizeEnrollmentService(trustedDevices,
            approvalRequests, mfa, qrTokens, EnrollmentPolicy.standard(), clock);
    private final ClaimEnrollmentService claimEnrollment = new ClaimEnrollmentService(sessionService,
            approvalRequests, trustedDevices, EnrollmentPolicy.standard(), clock);

    private TrustedDevice phone;

    @BeforeEach
    void aliceHasAPrimaryPhoneATrustedTabletAndAWatchOnARestrictedSession() {
        phone = DomainFixtures.trustedDevice(new DeviceInstallation(ALICE, Channel.MOBILE, PHONE),
                DevicePlatform.ANDROID, "{phone-key}", NOW.minusSeconds(3600));
        TrustedDevice tablet = DomainFixtures.trustedDevice(new DeviceInstallation(ALICE, Channel.MOBILE, TABLET),
                DevicePlatform.IOS, "{tablet-key}", NOW.minusSeconds(1800));
        devices.rows.put(phone.id(), phone);
        devices.rows.put(tablet.id(), tablet);
        devices.primaries.put(new InMemoryTrustedDeviceRepository.Key(ALICE, Channel.MOBILE), phone.id());
        NewSession phoneStart = DomainFixtures.mobileSession(PHONE_TOKEN.sessionId(), ALICE, PHONE, NOW);
        sessions.create(Session.start(phoneStart, sessionPolicy()), PHONE_TOKEN);
        NewSession tabletStart = DomainFixtures.mobileSession(TABLET_TOKEN.sessionId(), ALICE, TABLET, NOW);
        sessions.create(Session.start(tabletStart, sessionPolicy()), TABLET_TOKEN);
        NewSession watchStart = DomainFixtures.mobileSession(WATCH_TOKEN.sessionId(), ALICE, WATCH, NOW);
        sessions.create(Session.startRestricted(watchStart, DevicePolicy.standard()), WATCH_TOKEN);
        when(mfa.create(any())).thenReturn(new CreateResult.Created("mfa-7", NOW.plus(Duration.ofMinutes(5))));
        when(qrTokens.next()).thenReturn(QR_TOKEN);
        when(tokens.next(any(), any())).thenReturn(NEW_TOKEN);
        when(sealer.seal(eq("{watch-kenc}"), eq(NEW_TOKEN), any())).thenReturn("jwe.token");
    }

    @Test
    void theWatchRequestsApprovalWithoutCreatingATrustedBinding() {
        RequestApprovalResult result = requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS));

        assertThat(result).isInstanceOf(RequestApprovalResult.WaitingApproval.class);
        RequestApprovalResult.WaitingApproval waiting = (RequestApprovalResult.WaitingApproval) result;
        assertThat(waiting.enrollmentId()).isEqualTo(ENROLLMENT);
        assertThat(waiting.expiresAt()).isEqualTo(NOW.plus(Duration.ofHours(24))); // the request waits a day (slice 11)
        DeviceEnrollment stored = enrollments.only();
        assertThat(stored.purpose()).isEqualTo(EnrollmentPurpose.TRUST_DEVICE_APPROVAL);
        assertThat(stored.state()).isEqualTo(EnrollmentState.WAITING_APPROVAL);
        assertThat(stored.candidateKey().publicJwk()).isEqualTo(WATCH_KEY);
        assertThat(stored.candidateKey().platform()).isEqualTo(DevicePlatform.IOS);
        assertThat(stored.targetDeviceId()).isNull();
        assertThat(devices.findLive(ALICE, Channel.MOBILE, WATCH)).isEmpty();
        assertThat(requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, "{different-key}", DevicePlatform.IOS)))
                .isInstanceOf(RequestApprovalResult.Conflict.class);

        // The same session asking again gets the same request; the status poll says it waits.
        assertThat(requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, null, null)))
                .isEqualTo(new RequestApprovalResult.WaitingApproval(ENROLLMENT, stored.expiresAt()));
        assertThat(enrollments.rows).hasSize(1);
        assertThat(approvalStatus.status(new ApprovalStatusCommand(WATCH_SESSION)))
                .isEqualTo(new ApprovalStatusResult.Status(ENROLLMENT, EnrollmentState.WAITING_APPROVAL, stored.expiresAt()));
    }

    @Test
    void anUnknownDeviceMustSendItsKeyAndTheQuotaAndSessionKindAreEnforced() {
        assertThat(requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, null, DevicePlatform.IOS)))
                .isInstanceOf(RequestApprovalResult.DeviceKeyRequired.class);
        assertThat(requestApproval.request(new RequestApprovalCommand(PHONE_SESSION, WATCH_KEY, DevicePlatform.IOS)))
                .isInstanceOf(RequestApprovalResult.Conflict.class); // an ACTIVE session is not a restricted one
        assertThat(approvalStatus.status(new ApprovalStatusCommand(WATCH_SESSION))).isInstanceOf(ApprovalStatusResult.NoRequest.class);

        // Three installations already wait: the fourth is refused before any row is written.
        for (int i = 0; i < 3; i++) {
            DeviceInstallation other = new DeviceInstallation(ALICE, Channel.MOBILE, new DeviceId("other-" + i));
            DeviceEnrollment waiting = DomainFixtures.approvalRequest(other, null, NOW.plusSeconds(600));
            enrollments.rows.put(waiting.id(), waiting);
        }
        assertThat(requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS)))
                .isInstanceOf(RequestApprovalResult.TooManyPending.class);
        assertThat(enrollments.rows).hasSize(3);
        assertThat(devices.findLive(ALICE, Channel.MOBILE, WATCH)).isEmpty();
    }

    @Test
    void onlyThePrimaryDeviceSeesAndApprovesTheRequestWithFaceAndOtp() {
        requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS));

        assertThat(listPendingDevices.pending(new ListPendingDevicesCommand(TABLET_SESSION)))
                .isInstanceOf(ListPendingDevicesResult.NotPrimaryDevice.class);
        assertThat(listPendingDevices.pending(new ListPendingDevicesCommand(WATCH_SESSION)))
                .isInstanceOf(ListPendingDevicesResult.NotPrimaryDevice.class); // restricted sessions never list
        assertThat(approveEnrollment.approve(new ApproveEnrollmentCommand(TABLET_SESSION, ENROLLMENT)))
                .isInstanceOf(ApproveEnrollmentResult.NotPrimaryDevice.class);
        verifyNoInteractions(mfa);

        ListPendingDevicesResult listed = listPendingDevices.pending(new ListPendingDevicesCommand(PHONE_SESSION));
        assertThat(listed).isInstanceOf(ListPendingDevicesResult.Pending.class);
        List<com.vpbank.dcp.auth.application.result.PendingDeviceSummary> pendingDevices =
                ((ListPendingDevicesResult.Pending) listed).devices();
        assertThat(pendingDevices).hasSize(1);
        assertThat(pendingDevices.get(0).enrollmentId()).isEqualTo(ENROLLMENT);
        assertThat(pendingDevices.get(0).deviceId()).isEqualTo(WATCH);
        assertThat(pendingDevices.get(0).platform()).isEqualTo(DevicePlatform.IOS);

        ApproveEnrollmentResult approved = approveEnrollment.approve(new ApproveEnrollmentCommand(PHONE_SESSION, ENROLLMENT));
        assertThat(approved).isEqualTo(new ApproveEnrollmentResult.MfaRequired("mfa-7", NOW.plus(Duration.ofMinutes(5))));
        verify(mfa).create(argThat((MfaTransactionRequest request) -> request.purpose() == EnrollmentPurpose.TRUST_DEVICE_APPROVAL
                && request.factors().equals(List.of(MfaFactor.FACE, MfaFactor.OTP))
                && request.authOperationId().equals(ENROLLMENT)));
        DeviceEnrollment stored = enrollments.only();
        assertThat(stored.actorDeviceId()).isEqualTo(phone.id());
        assertThat(stored.mfaTransactionId()).isEqualTo("mfa-7");

        // Claiming before the token exists is a conflict.
        assertThat(claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, QR_TOKEN, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.Conflict.class);
    }

    /** The phone lost approve's answer, or sent approve twice: the same FACE + OTP check again, nothing rewritten. */
    @Test
    void aRepeatedApproveByTheSameDeviceGetsTheSameCheckAgain() {
        requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS));
        ApproveEnrollmentCommand approve = new ApproveEnrollmentCommand(PHONE_SESSION, ENROLLMENT);
        ApproveEnrollmentResult first = approveEnrollment.approve(approve);
        DeviceEnrollment afterFirst = enrollments.only();

        assertThat(approveEnrollment.approve(approve)).isEqualTo(first);

        assertThat(enrollments.only()).isEqualTo(afterFirst); // same row, same version
        // Both calls sent the MFA service the same create, so it can answer the repeat with the first check.
        var creates = org.mockito.ArgumentCaptor.forClass(MfaTransactionRequest.class);
        verify(mfa, org.mockito.Mockito.times(2)).create(creates.capture());
        assertThat(creates.getAllValues().get(1)).isEqualTo(creates.getAllValues().get(0));
    }

    @Test
    void aRepeatedApproveIsRefusedWhenTheMfaServiceAnswersWithAnotherCheck() {
        requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS));
        approveEnrollment.approve(new ApproveEnrollmentCommand(PHONE_SESSION, ENROLLMENT));
        when(mfa.create(any())).thenReturn(new CreateResult.Created("mfa-8", NOW.plus(Duration.ofMinutes(5))));

        assertThat(approveEnrollment.approve(new ApproveEnrollmentCommand(PHONE_SESSION, ENROLLMENT)))
                .isInstanceOf(ApproveEnrollmentResult.Conflict.class);

        assertThat(enrollments.only().mfaTransactionId()).isEqualTo("mfa-7"); // the request keeps the first check
    }

    @Test
    void aRequestOneDeviceApprovedCannotBeApprovedByAnotherPrimaryDevice() {
        requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS));
        approveEnrollment.approve(new ApproveEnrollmentCommand(PHONE_SESSION, ENROLLMENT));
        // The tablet became the primary device after the phone approved.
        TrustedDevice tablet = devices.findLive(ALICE, Channel.MOBILE, TABLET).orElseThrow();
        devices.primaries.put(new InMemoryTrustedDeviceRepository.Key(ALICE, Channel.MOBILE), tablet.id());

        assertThat(approveEnrollment.approve(new ApproveEnrollmentCommand(TABLET_SESSION, ENROLLMENT)))
                .isInstanceOf(ApproveEnrollmentResult.Conflict.class);

        verify(mfa).create(any()); // only the phone's approve reached the MFA service
        assertThat(enrollments.only().actorDeviceId()).isEqualTo(phone.id());
    }

    @Test
    void theTokenIsIssuedOnlyAfterMfaPassedAndOnlyToTheApprovingDevice() {
        requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS));
        assertThat(authorizeEnrollment.authorize(new AuthorizeEnrollmentCommand(PHONE_SESSION, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.Conflict.class); // not approved yet
        approveEnrollment.approve(new ApproveEnrollmentCommand(PHONE_SESSION, ENROLLMENT));

        when(mfa.check(any())).thenReturn(new CheckResult.Pending());
        assertThat(authorizeEnrollment.authorize(new AuthorizeEnrollmentCommand(PHONE_SESSION, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.MfaPending.class);
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.WAITING_APPROVAL);

        doReturn(new CheckResult.Passed("receipt")).when(mfa).check(argThat(check ->
                check.mfaTransactionId().equals("mfa-7") && check.factorClaim().equals("FACE+OTP")
                        && check.purpose() == EnrollmentPurpose.TRUST_DEVICE_APPROVAL
                        && check.customerId().equals(ALICE)));
        AuthorizeEnrollmentResult authorized = authorizeEnrollment.authorize(new AuthorizeEnrollmentCommand(PHONE_SESSION, ENROLLMENT));
        assertThat(authorized).isEqualTo(new AuthorizeEnrollmentResult.Authorized(ENROLLMENT, QR_TOKEN, NOW.plusSeconds(180)));
        DeviceEnrollment stored = enrollments.only();
        assertThat(stored.state()).isEqualTo(EnrollmentState.WAITING_AUTHORIZATION);
        assertThat(stored.authorizationTokenDigest()).isNotEqualTo(QR_TOKEN).hasSize(43);
        assertThat(stored.mfaMethod()).isEqualTo("FACE+OTP");
        assertThat(approvalStatus.status(new ApprovalStatusCommand(WATCH_SESSION)))
                .isEqualTo(new ApprovalStatusResult.Status(ENROLLMENT, EnrollmentState.WAITING_AUTHORIZATION, stored.expiresAt()));

    }

    /** The phone lost authorize's answer, or sent it twice: only the digest was kept, so it gets a new token. */
    @Test
    void aRepeatedAuthorizeReplacesTheTokenAndKeepsItsDeadlineAndTheClaimAttempts() {
        authorizeTheWatch();
        claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, "wrong-token", "{watch-kenc}"));
        DeviceEnrollment afterFirst = enrollments.only();
        String secondToken = "r".repeat(43);
        when(qrTokens.next()).thenReturn(secondToken);

        AuthorizeEnrollmentResult again = authorizeEnrollment.authorize(new AuthorizeEnrollmentCommand(PHONE_SESSION, ENROLLMENT));

        assertThat(again).isEqualTo(new AuthorizeEnrollmentResult.Authorized(ENROLLMENT, secondToken, NOW.plusSeconds(180)));
        DeviceEnrollment reissued = enrollments.only();
        assertThat(reissued.state()).isEqualTo(EnrollmentState.WAITING_AUTHORIZATION);
        assertThat(reissued.authorizationTokenDigest()).isNotEqualTo(afterFirst.authorizationTokenDigest());
        assertThat(reissued.authorizationExpiresAt()).isEqualTo(afterFirst.authorizationExpiresAt());
        assertThat(reissued.authorizationAttempts()).isEqualTo(1); // the wrong claim before the repeat still counts
        verify(mfa).check(any()); // the MFA outcome is not read again

        // The first token no longer opens anything; the new one does.
        assertThat(claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, QR_TOKEN, "{watch-kenc}")))
                .isEqualTo(new ClaimEnrollmentResult.WrongAuthorization(3));
        assertThat(claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, secondToken, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.Trusted.class);
    }

    @Test
    void aRepeatedAuthorizeIsOnlyForTheApprovingDeviceAndOnlyWhileTheRequestIsOpen() {
        authorizeTheWatch();
        DeviceEnrollment authorized = enrollments.only();

        // The tablet became the primary device after the phone collected the token.
        TrustedDevice tablet = devices.findLive(ALICE, Channel.MOBILE, TABLET).orElseThrow();
        devices.primaries.put(new InMemoryTrustedDeviceRepository.Key(ALICE, Channel.MOBILE), tablet.id());
        assertThat(authorizeEnrollment.authorize(new AuthorizeEnrollmentCommand(TABLET_SESSION, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.Conflict.class);
        assertThat(enrollments.only()).isEqualTo(authorized);

        // Once the watch has claimed, it is the primary device and the request is closed: nothing to hand out.
        devices.primaries.put(new InMemoryTrustedDeviceRepository.Key(ALICE, Channel.MOBILE), phone.id());
        claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, QR_TOKEN, "{watch-kenc}"));
        assertThat(authorizeEnrollment.authorize(new AuthorizeEnrollmentCommand(PHONE_SESSION, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.NotPrimaryDevice.class);
        verify(qrTokens).next(); // only the first token was ever made
    }

    @Test
    void mfaFailureOrExpiryEndsTheRequestAndAnMfaOutageChangesNothing() {
        requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS));
        approveEnrollment.approve(new ApproveEnrollmentCommand(PHONE_SESSION, ENROLLMENT));
        doReturn(new CheckResult.Failed()).when(mfa).check(any());
        assertThat(authorizeEnrollment.authorize(new AuthorizeEnrollmentCommand(PHONE_SESSION, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.MfaFailed.class);
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.FAILED);
        assertThat(approvalStatus.status(new ApprovalStatusCommand(WATCH_SESSION)))
                .isEqualTo(new ApprovalStatusResult.Status(ENROLLMENT, EnrollmentState.FAILED, enrollments.only().expiresAt()));

        enrollments.rows.clear();
        enrollments.bySession.clear();
        requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS));
        approveEnrollment.approve(new ApproveEnrollmentCommand(PHONE_SESSION, ENROLLMENT));
        doReturn(new CheckResult.Rejected()).when(mfa).check(any());
        assertThat(authorizeEnrollment.authorize(new AuthorizeEnrollmentCommand(PHONE_SESSION, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.Rejected.class);
        org.mockito.Mockito.doThrow(new PartnerUnavailableException("MFA")).when(mfa).check(any());
        assertThat(authorizeEnrollment.authorize(new AuthorizeEnrollmentCommand(PHONE_SESSION, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.Unavailable.class);
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.WAITING_APPROVAL);
        assertThat(enrollments.only().hasApprovalInProgress()).isTrue();
    }

    @Test
    void theClaimMakesTheWatchTrustedAndPrimaryAndOpensAnActiveSessionWhileThePhoneStaysTrusted() {
        authorizeTheWatch();

        ClaimEnrollmentResult result = claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, QR_TOKEN, "{watch-kenc}"));

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
        assertThat(confirmation.enrollment().state()).isEqualTo(EnrollmentState.COMPLETED);
        assertThat(confirmation.enrollment().authorizationConsumedAt()).isEqualTo(NOW);

        // The restricted session is gone; the new ACTIVE session belongs to the watch.
        assertThat(sessions.findByToken(WATCH_TOKEN)).isEmpty();
        Session active = sessions.findByToken(NEW_TOKEN).orElseThrow().session();
        assertThat(active.status()).isEqualTo(SessionStatus.ACTIVE);
        assertThat(active.deviceId()).isEqualTo(WATCH);
        // The BFF would no longer admit that session; if it did, the completed request cannot be claimed again.
        assertThat(claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, QR_TOKEN, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.Conflict.class);
    }

    /** The database fails at the trust commit: the request still waits for its token and the watch claims again. */
    @Test
    void aDatabaseFailureAtTheCommitLeavesTheRequestAndTheSessionForAnotherClaim() {
        authorizeTheWatch();
        devices.unavailable = true;

        assertThat(claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, QR_TOKEN, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.Unavailable.class);
        DeviceEnrollment stillWaiting = enrollments.only();
        assertThat(stillWaiting.state()).isEqualTo(EnrollmentState.WAITING_AUTHORIZATION);
        assertThat(stillWaiting.authorizationAttempts()).isEqualTo(1); // the attempt was counted before the commit
        assertThat(sessions.findByToken(WATCH_TOKEN)).isPresent();
        verify(tokens, never()).next(any(), any());

        devices.unavailable = false;
        assertThat(claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, QR_TOKEN, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.Trusted.class);
        assertThat(devices.confirmations).hasSize(1);
        assertThat(sessions.findByToken(WATCH_TOKEN)).isEmpty();
    }

    @Test
    void aClaimFromASessionAlreadyGoneOrAfterAnotherClaimCommittedCommitsNothing() {
        authorizeTheWatch();
        devices.committedEnrollments.add(ENROLLMENT); // another claim of the watch committed meanwhile

        assertThat(claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, QR_TOKEN, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.Conflict.class);
        assertThat(devices.confirmations).isEmpty();
        assertThat(sessions.findByToken(WATCH_TOKEN)).isPresent();

        devices.committedEnrollments.clear();
        sessions.rows.clear(); // logged out after the BFF admitted the claim
        assertThat(claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, QR_TOKEN, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.Conflict.class);
        assertThat(devices.confirmations).isEmpty();
        verify(tokens, never()).next(any(), any());
    }

    /** A logout between the commit and the session's consumption: the watch stays trusted, no ACTIVE session. */
    @Test
    void aSessionEndedRightAfterTheClaimCommittedLeavesTheWatchTrustedWithoutAnActiveSession() {
        authorizeTheWatch();
        devices.afterTrustConfirmed = sessions.rows::clear;

        assertThat(claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, QR_TOKEN, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.Conflict.class);
        assertThat(devices.confirmations).hasSize(1);
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE))
                .contains(devices.findLive(ALICE, Channel.MOBILE, WATCH).orElseThrow().id());
        verify(tokens, never()).next(any(), any());
    }

    @Test
    void wrongTokensAreCountedBeforeTheCheckAndTheFifthOneEndsTheRequestAndTheSession() {
        authorizeTheWatch();

        for (int attemptsLeft = 4; attemptsLeft >= 1; attemptsLeft--) {
            assertThat(claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, "wrong", "{watch-kenc}")))
                    .isEqualTo(new ClaimEnrollmentResult.WrongAuthorization(attemptsLeft));
        }
        assertThat(enrollments.only().authorizationAttempts()).isEqualTo(4);
        assertThat(claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, "wrong", "{watch-kenc}")))
                .isEqualTo(new ClaimEnrollmentResult.WrongAuthorization(0));
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.FAILED);
        assertThat(sessions.findByToken(WATCH_TOKEN)).isEmpty();
        assertThat(devices.findLive(ALICE, Channel.MOBILE, WATCH)).isEmpty();
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE)).contains(phone.id());
    }

    @Test
    void anExpiredTokenEndsTheRequestAndTheSessionAndAnotherDeviceCannotClaim() {
        authorizeTheWatch();
        // The tablet is another device: the watch's request is not its request, even with the right token.
        AdmittedSession restrictedTablet = new AdmittedSession(SessionId.random(), ALICE, Channel.MOBILE, TABLET,
                SessionStatus.NEED_TRUSTED_DEVICE);
        assertThat(claimEnrollment.claim(new ClaimEnrollmentCommand(restrictedTablet, QR_TOKEN, "{tablet-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.Conflict.class);
        assertThat(enrollments.only().authorizationAttempts()).isZero();

        Clock later = Clock.fixed(NOW.plusSeconds(180), ZoneOffset.UTC);
        SessionService laterSessionService = new SessionService(sessions, sealer, tokens, SessionId::random,
                sessionPolicy(), DevicePolicy.standard(), later);
        ClaimEnrollmentService laterClaim = new ClaimEnrollmentService(laterSessionService,
                new ApprovalRequests(enrollments, later), trustedDevices, EnrollmentPolicy.standard(), later);
        assertThat(laterClaim.claim(new ClaimEnrollmentCommand(WATCH_SESSION, QR_TOKEN, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.AuthorizationExpired.class);
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.EXPIRED);
        assertThat(sessions.findByToken(WATCH_TOKEN)).isEmpty();
    }

    @Test
    void aRepeatedAuthorizeAfterTheTokensDeadlineHandsOutNothingAndCannotExtendIt() {
        authorizeTheWatch();
        DeviceEnrollment authorized = enrollments.only();
        Clock later = Clock.fixed(NOW.plusSeconds(180), ZoneOffset.UTC);
        AuthorizeEnrollmentService laterAuthorize = new AuthorizeEnrollmentService(trustedDevices,
                new ApprovalRequests(enrollments, later), mfa, qrTokens, EnrollmentPolicy.standard(), later);

        assertThat(laterAuthorize.authorize(new AuthorizeEnrollmentCommand(PHONE_SESSION, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.Conflict.class);

        assertThat(enrollments.only()).isEqualTo(authorized);
        verify(qrTokens).next(); // no second token
    }

    @Test
    void theRequestBelongsToTheDeviceSoALaterLoginSeesItAndClaimsIt() {
        requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS));

        // The watch's restricted session ran out; the customer logs in on the watch again.
        OpaqueToken laterWatchToken = new OpaqueToken("s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000044:" + "E".repeat(43));
        NewSession laterWatchStart = DomainFixtures.mobileSession(laterWatchToken.sessionId(), ALICE, WATCH, NOW);
        sessions.create(Session.startRestricted(laterWatchStart, DevicePolicy.standard()), laterWatchToken);
        AdmittedSession laterWatchLogin = new AdmittedSession(laterWatchToken.sessionId(), ALICE, Channel.MOBILE, WATCH,
                SessionStatus.NEED_TRUSTED_DEVICE);

        // Asking again gives the same request: one open request per device. (A service that would mint a new ID shows
        // that nothing new is created.)
        RequestApprovalService laterLoginRequest = new RequestApprovalService(approvalRequests, enrollmentTransactions,
                trustedDevices, EnrollmentId::random, EnrollmentPolicy.standard(), clock);
        assertThat(laterLoginRequest.request(new RequestApprovalCommand(laterWatchLogin, null, null)))
                .isEqualTo(new RequestApprovalResult.WaitingApproval(ENROLLMENT, NOW.plus(Duration.ofHours(24))));
        assertThat(enrollments.rows).hasSize(1);

        approveEnrollment.approve(new ApproveEnrollmentCommand(PHONE_SESSION, ENROLLMENT));
        when(mfa.check(any())).thenReturn(new CheckResult.Passed("receipt"));
        authorizeEnrollment.authorize(new AuthorizeEnrollmentCommand(PHONE_SESSION, ENROLLMENT));
        assertThat(approvalStatus.status(new ApprovalStatusCommand(laterWatchLogin))).isEqualTo(new ApprovalStatusResult.Status(
                ENROLLMENT, EnrollmentState.WAITING_AUTHORIZATION, NOW.plus(Duration.ofHours(24))));

        ClaimEnrollmentResult claimed = claimEnrollment.claim(new ClaimEnrollmentCommand(laterWatchLogin, QR_TOKEN, "{watch-kenc}"));

        assertThat(claimed).isInstanceOf(ClaimEnrollmentResult.Trusted.class);
        assertThat(sessions.findByToken(laterWatchToken)).isEmpty(); // the session that claimed is consumed
        assertThat(devices.findPrimary(ALICE, Channel.MOBILE))
                .contains(devices.findLive(ALICE, Channel.MOBILE, WATCH).orElseThrow().id());
        assertThat(devices.confirmations.getFirst().enrollment().id()).isEqualTo(ENROLLMENT);
        assertThat(devices.confirmations.getFirst().enrollment().state()).isEqualTo(EnrollmentState.COMPLETED);
    }

    @Test
    void aClosedRequestIsReportedAndALaterLoginMayAskAgain() {
        requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS));
        approveEnrollment.approve(new ApproveEnrollmentCommand(PHONE_SESSION, ENROLLMENT));
        doReturn(new CheckResult.Failed()).when(mfa).check(any());
        authorizeEnrollment.authorize(new AuthorizeEnrollmentCommand(PHONE_SESSION, ENROLLMENT));
        assertThat(enrollments.only().state()).isEqualTo(EnrollmentState.FAILED);

        // The same login cannot ask twice (one request per session, as the store keeps it); its status says why.
        EnrollmentId secondRequest = EnrollmentId.random();
        RequestApprovalService secondRequestService = new RequestApprovalService(approvalRequests, enrollmentTransactions,
                trustedDevices, () -> secondRequest, EnrollmentPolicy.standard(), clock);
        assertThat(secondRequestService.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS)))
                .isInstanceOf(RequestApprovalResult.Conflict.class);
        assertThat(approvalStatus.status(new ApprovalStatusCommand(WATCH_SESSION)))
                .isEqualTo(new ApprovalStatusResult.Status(ENROLLMENT, EnrollmentState.FAILED, NOW.plus(Duration.ofHours(24))));

        // A later login of the watch opens a new request, which is now the device's request.
        AdmittedSession laterWatchLogin = new AdmittedSession(SessionId.random(), ALICE, Channel.MOBILE, WATCH,
                SessionStatus.NEED_TRUSTED_DEVICE);
        assertThat(secondRequestService.request(new RequestApprovalCommand(laterWatchLogin, null, null)))
                .isInstanceOf(RequestApprovalResult.DeviceKeyRequired.class);
        assertThat(secondRequestService.request(new RequestApprovalCommand(laterWatchLogin, WATCH_KEY, DevicePlatform.IOS)))
                .isEqualTo(new RequestApprovalResult.WaitingApproval(secondRequest, NOW.plus(Duration.ofHours(24))));
        assertThat(approvalStatus.status(new ApprovalStatusCommand(WATCH_SESSION)))
                .isEqualTo(new ApprovalStatusResult.Status(secondRequest, EnrollmentState.WAITING_APPROVAL,
                        NOW.plus(Duration.ofHours(24))));
    }

    @Test
    void theOldestDeviceExpiresWhenTheApprovedOneWouldExceedTheCap() {
        for (int i = 0; i < 3; i++) {
            DeviceInstallation extraInstallation =
                    new DeviceInstallation(ALICE, Channel.MOBILE, new DeviceId("extra-" + i));
            TrustedDevice extra = DomainFixtures.trustedDevice(extraInstallation, DevicePlatform.IOS, "{k}",
                    NOW.minusSeconds(7200 + i));
            devices.rows.put(extra.id(), extra);
        }
        authorizeTheWatch(); // phone, tablet and 3 extras already fill the device cap

        claimEnrollment.claim(new ClaimEnrollmentCommand(WATCH_SESSION, QR_TOKEN, "{watch-kenc}"));

        assertThat(devices.findLive(ALICE, Channel.MOBILE, new DeviceId("extra-2"))).isEmpty();
        assertThat(devices.findLive(ALICE, Channel.MOBILE)).hasSize(5);
    }

    @Test
    void aSessionThatStartedThePrimaryEnrollmentCannotAlsoAskForApproval() {
        KeyExchangeStart start = KeyExchangeStart.builder()
                .enrollmentId(EnrollmentId.random())
                .newDeviceSession(WATCH_SESSION)
                .deviceKey(new DeviceKey(WATCH_KEY, DevicePlatform.IOS))
                .serverPublicJwk("{srv-pub}")
                .serverPrivateJwk("{srv-priv}")
                .challengeDigest("digest")
                .sealedChallenge("jwe.challenge")
                .build();
        EnrollmentTransaction startedOnThisSession = EnrollmentTransaction.keyExchange(start);
        enrollmentTransactions.open(startedOnThisSession);

        assertThat(requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS)))
                .isInstanceOf(RequestApprovalResult.Conflict.class);
        assertThat(enrollments.rows).isEmpty();
        assertThat(devices.findLive(ALICE, Channel.MOBILE, WATCH)).isEmpty();

        // A later login of the same watch is another session: the earlier login's transaction does not block it.
        AdmittedSession laterWatchLogin = new AdmittedSession(SessionId.random(), ALICE, Channel.MOBILE, WATCH,
                SessionStatus.NEED_TRUSTED_DEVICE);
        assertThat(requestApproval.request(new RequestApprovalCommand(laterWatchLogin, WATCH_KEY, DevicePlatform.IOS)))
                .isInstanceOf(RequestApprovalResult.WaitingApproval.class);
    }

    @Test
    void theKindOfAdmittedSessionMustFitTheRoute() {
        authorizeTheWatch();

        // The primary phone on a restricted session (its trust lapsed after the BFF admitted it) never approves.
        AdmittedSession restrictedPhone = new AdmittedSession(PHONE_TOKEN.sessionId(), ALICE, Channel.MOBILE, PHONE,
                SessionStatus.NEED_TRUSTED_DEVICE);
        assertThat(listPendingDevices.pending(new ListPendingDevicesCommand(restrictedPhone)))
                .isInstanceOf(ListPendingDevicesResult.NotPrimaryDevice.class);
        assertThat(approveEnrollment.approve(new ApproveEnrollmentCommand(restrictedPhone, ENROLLMENT)))
                .isInstanceOf(ApproveEnrollmentResult.NotPrimaryDevice.class);
        assertThat(authorizeEnrollment.authorize(new AuthorizeEnrollmentCommand(restrictedPhone, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.NotPrimaryDevice.class);

        // The watch's request seen from an ACTIVE session of the same session ID: not the new-device routes.
        AdmittedSession activeWatch = new AdmittedSession(WATCH_TOKEN.sessionId(), ALICE, Channel.MOBILE, WATCH,
                SessionStatus.ACTIVE);
        assertThat(approvalStatus.status(new ApprovalStatusCommand(activeWatch))).isInstanceOf(ApprovalStatusResult.NoRequest.class);
        assertThat(claimEnrollment.claim(new ClaimEnrollmentCommand(activeWatch, QR_TOKEN, "{watch-kenc}")))
                .isInstanceOf(ClaimEnrollmentResult.Conflict.class);
        assertThat(enrollments.only().authorizationAttempts()).isZero();
        assertThat(sessions.findByToken(WATCH_TOKEN)).isPresent();
    }

    private void authorizeTheWatch() {
        requestApproval.request(new RequestApprovalCommand(WATCH_SESSION, WATCH_KEY, DevicePlatform.IOS));
        approveEnrollment.approve(new ApproveEnrollmentCommand(PHONE_SESSION, ENROLLMENT));
        when(mfa.check(any())).thenReturn(new CheckResult.Passed("receipt"));
        assertThat(authorizeEnrollment.authorize(new AuthorizeEnrollmentCommand(PHONE_SESSION, ENROLLMENT)))
                .isInstanceOf(AuthorizeEnrollmentResult.Authorized.class);
    }

    private static SessionPolicy sessionPolicy() {
        return new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20), Duration.ofSeconds(30));
    }
}
