package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.ApprovalStatusCommand;
import com.vpbank.dcp.auth.application.command.ApproveEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.AuthorizeEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.ClaimEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.ListPendingDevicesCommand;
import com.vpbank.dcp.auth.application.command.RequestApprovalCommand;
import com.vpbank.dcp.auth.application.port.in.ApprovalStatusUseCase;
import com.vpbank.dcp.auth.application.port.in.ApproveEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.AuthorizeEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.ClaimEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.ListPendingDevicesUseCase;
import com.vpbank.dcp.auth.application.port.in.RequestApprovalUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.AuthorizationTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CheckResult;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CreateResult;
import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.port.out.model.MfaCheckRequest;
import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentRepository;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.application.result.ApprovalStatusResult;
import com.vpbank.dcp.auth.application.result.ApproveEnrollmentResult;
import com.vpbank.dcp.auth.application.result.AuthorizeEnrollmentResult;
import com.vpbank.dcp.auth.application.result.ClaimEnrollmentResult;
import com.vpbank.dcp.auth.application.result.KnownDeviceSummary;
import com.vpbank.dcp.auth.application.result.ListPendingDevicesResult;
import com.vpbank.dcp.auth.application.result.PendingDeviceSummary;
import com.vpbank.dcp.auth.application.result.RequestApprovalResult;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.MfaFactor;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * A new device trusted and made primary by the customer's current primary device (DD 20 §4, slice 6).
 * The new device, on its restricted session, registers a PENDING row and an approval request. The
 * primary device, on its ACTIVE session, lists the requests, approves one (FACE + OTP at the MFA
 * service) and receives a one-time authorization token to show as a QR. The new device claims that
 * token from the same restricted session; the trust commit then makes it trusted and primary, ends the
 * restricted session and issues a full ACTIVE one. Auth keeps only the token's digest.
 */
@RequiredArgsConstructor
public final class DeviceApprovalService implements RequestApprovalUseCase, ApprovalStatusUseCase,
        ListPendingDevicesUseCase, ApproveEnrollmentUseCase, AuthorizeEnrollmentUseCase, ClaimEnrollmentUseCase {
    /** The approving device confirms with FACE and OTP (decision 2026-10-25). */
    private static final List<MfaFactor> FACE_AND_OTP = List.of(MfaFactor.FACE, MfaFactor.OTP);
    /** The last wrong token leaves no attempt; the enrollment is already failed when it is reported. */
    private static final int NO_ATTEMPTS_LEFT = 0;

    @NonNull private final SessionStore sessionStore;
    @NonNull private final EnrollmentRepository enrollmentRepository;
    @NonNull private final TrustedDeviceRepository trustedDeviceRepository;
    @NonNull private final TrustedDeviceService trustedDeviceService;
    @NonNull private final MfaTransactionPort mfaTransactionPort;
    @NonNull private final AuthorizationTokenGenerator authorizationTokenGenerator;
    @NonNull private final TokenEnvelopeSealer tokenEnvelopeSealer;
    @NonNull private final OpaqueTokenGenerator opaqueTokenGenerator;
    @NonNull private final Supplier<EnrollmentId> enrollmentIdGenerator;
    @NonNull private final Supplier<SessionId> sessionIdGenerator;
    @NonNull private final EnrollmentPolicy enrollmentPolicy;
    @NonNull private final SessionPolicy sessionPolicy;
    @NonNull private final Clock clock;

    // ---- the new device ----

    @Override
    public RequestApprovalResult request(RequestApprovalCommand command) {
        try {
            Optional<StoredSession> restrictedSession = findRestrictedSession(command.token());
            if (restrictedSession.isEmpty()) {
                return new RequestApprovalResult.SessionGone();
            }
            Session session = restrictedSession.get().session();

            // The primary enrollment (FACE on this device) already started on this session.
            if (session.enrollment() != null) {
                return new RequestApprovalResult.Conflict();
            }

            // A repeated request from the same session gets the same answer.
            Optional<DeviceEnrollment> earlierRequest =
                    enrollmentRepository.findBySession(session.customerId(), session.deviceId(), session.id());
            if (earlierRequest.isPresent()) {
                return answerForEarlier(earlierRequest.get());
            }

            Optional<KnownDeviceSummary> knownDevice = trustedDeviceService.knownDevice(
                    session.customerId(),
                    session.channel(),
                    session.deviceId());

            // An unknown installation must send both; a known live row keeps what Auth already stores.
            String devicePublicJwk = command.devicePublicJwk();
            DevicePlatform platform = command.platform();
            boolean unknownDeviceWithoutKey = knownDevice.isEmpty() && (devicePublicJwk == null || platform == null);
            if (unknownDeviceWithoutKey) {
                return new RequestApprovalResult.DeviceKeyRequired();
            }

            String correlationId = session.id().toString();
            Optional<TrustedDevice> targetDevice = trustedDeviceService.registerPendingDevice(
                    session.customerId(),
                    session.channel(),
                    session.deviceId(),
                    platform,
                    devicePublicJwk,
                    enrollmentPolicy,
                    correlationId);
            if (targetDevice.isEmpty()) {
                return new RequestApprovalResult.TooManyPending();
            }

            DeviceEnrollment freshRequest = DeviceEnrollment.requestApproval(
                    enrollmentIdGenerator.get(),
                    session.customerId(),
                    session.channel(),
                    session.deviceId(),
                    targetDevice.get().id(),
                    session.absoluteExpiresAt());
            DeviceEnrollment storedRequest = enrollmentRepository.create(freshRequest, session.id());

            // A race on the one-enrollment-per-session rule returns whatever that session created first.
            if (!storedRequest.id().equals(freshRequest.id())) {
                return answerForEarlier(storedRequest);
            }
            return new RequestApprovalResult.WaitingApproval(storedRequest.id(), storedRequest.expiresAt());
        } catch (RepositoryUnavailableException failure) {
            return new RequestApprovalResult.Unavailable();
        }
    }

    private RequestApprovalResult answerForEarlier(DeviceEnrollment earlierRequest) {
        boolean stillWaiting = earlierRequest.isApproval() && earlierRequest.isOpen(clock.instant());
        if (stillWaiting) {
            return new RequestApprovalResult.WaitingApproval(earlierRequest.id(), earlierRequest.expiresAt());
        }
        return new RequestApprovalResult.Conflict();
    }

    @Override
    public ApprovalStatusResult status(ApprovalStatusCommand command) {
        try {
            Optional<StoredSession> restrictedSession = findRestrictedSession(command.token());
            if (restrictedSession.isEmpty()) {
                return new ApprovalStatusResult.SessionGone();
            }
            Session session = restrictedSession.get().session();

            Optional<DeviceEnrollment> request =
                    enrollmentRepository.findBySession(session.customerId(), session.deviceId(), session.id());
            if (request.isEmpty() || !request.get().isApproval()) {
                return new ApprovalStatusResult.NoRequest();
            }
            DeviceEnrollment enrollment = request.get();

            // An open request past its window is reported as expired without touching the row.
            EnrollmentState state = enrollment.state();
            if (state.open() && !enrollment.isOpen(clock.instant())) {
                state = EnrollmentState.EXPIRED;
            }
            return new ApprovalStatusResult.Status(enrollment.id(), state, enrollment.expiresAt());
        } catch (RepositoryUnavailableException failure) {
            return new ApprovalStatusResult.Unavailable();
        }
    }

    // ---- the primary device ----

    @Override
    public ListPendingDevicesResult pending(ListPendingDevicesCommand command) {
        try {
            Optional<StoredSession> activeSession = findActiveSession(command.token());
            if (activeSession.isEmpty()) {
                return new ListPendingDevicesResult.SessionGone();
            }
            Session session = activeSession.get().session();

            Optional<TrustedDeviceId> primaryDeviceId = primaryDeviceIdOf(session);
            if (primaryDeviceId.isEmpty()) {
                return new ListPendingDevicesResult.NotPrimaryDevice();
            }

            Instant now = clock.instant();
            List<DeviceEnrollment> openApprovals =
                    enrollmentRepository.findOpenApprovals(session.customerId(), session.channel());
            List<TrustedDevice> liveDevices = trustedDeviceRepository.findLive(session.customerId(), session.channel());

            List<PendingDeviceSummary> summaries = new ArrayList<>();
            for (DeviceEnrollment approval : openApprovals) {
                if (!approval.isOpen(now)) {
                    continue;
                }
                Optional<TrustedDevice> targetDevice = findById(liveDevices, approval.targetDeviceId());
                if (targetDevice.isEmpty()) {
                    continue;
                }
                PendingDeviceSummary summary = new PendingDeviceSummary(
                        approval.id(),
                        approval.deviceId(),
                        targetDevice.get().platform(),
                        approval.state(),
                        approval.expiresAt());
                summaries.add(summary);
            }
            return new ListPendingDevicesResult.Pending(summaries);
        } catch (RepositoryUnavailableException failure) {
            return new ListPendingDevicesResult.Unavailable();
        }
    }

    @Override
    public ApproveEnrollmentResult approve(ApproveEnrollmentCommand command) {
        try {
            Optional<StoredSession> activeSession = findActiveSession(command.token());
            if (activeSession.isEmpty()) {
                return new ApproveEnrollmentResult.SessionGone();
            }
            Session session = activeSession.get().session();

            Optional<TrustedDeviceId> primaryDeviceId = primaryDeviceIdOf(session);
            if (primaryDeviceId.isEmpty()) {
                return new ApproveEnrollmentResult.NotPrimaryDevice();
            }

            Optional<DeviceEnrollment> waitingRequest = findOpenApproval(command.enrollmentId(), session,
                    EnrollmentState.WAITING_APPROVAL);
            if (waitingRequest.isEmpty() || waitingRequest.get().hasApprovalInProgress()) {
                return new ApproveEnrollmentResult.Conflict();
            }
            DeviceEnrollment enrollment = waitingRequest.get();

            MfaTransactionRequest mfaTransactionRequest = MfaTransactionRequest.builder()
                    .customerId(session.customerId())
                    .channel(session.channel())
                    .authOperationId(enrollment.id())
                    .purpose(enrollment.purpose())
                    .factors(FACE_AND_OTP)
                    .notAfter(enrollment.expiresAt())
                    .contextDigest(EnrollmentDigests.contextDigest(enrollment))
                    .build();
            CreateResult createResult = mfaTransactionPort.create(mfaTransactionRequest);

            return switch (createResult) {
                case CreateResult.NoUsableFactor() -> {
                    DeviceEnrollment failedEnrollment = enrollment.fail();
                    enrollmentRepository.saveIfCurrent(failedEnrollment);
                    yield new ApproveEnrollmentResult.NoUsableFactor();
                }
                case CreateResult.Created(String mfaTransactionId, Instant mfaExpiresAt) -> {
                    DeviceEnrollment approvedEnrollment = enrollment.approveBy(primaryDeviceId.get(), mfaTransactionId);
                    Optional<DeviceEnrollment> savedEnrollment = enrollmentRepository.saveIfCurrent(approvedEnrollment);
                    if (savedEnrollment.isEmpty()) {
                        yield new ApproveEnrollmentResult.Conflict();
                    }
                    Instant expiresAt = earlier(mfaExpiresAt, enrollment.expiresAt());
                    yield new ApproveEnrollmentResult.MfaRequired(mfaTransactionId, expiresAt);
                }
            };
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new ApproveEnrollmentResult.Unavailable();
        }
    }

    @Override
    public AuthorizeEnrollmentResult authorize(AuthorizeEnrollmentCommand command) {
        try {
            Optional<StoredSession> activeSession = findActiveSession(command.token());
            if (activeSession.isEmpty()) {
                return new AuthorizeEnrollmentResult.SessionGone();
            }
            Session session = activeSession.get().session();

            Optional<TrustedDeviceId> primaryDeviceId = primaryDeviceIdOf(session);
            if (primaryDeviceId.isEmpty()) {
                return new AuthorizeEnrollmentResult.NotPrimaryDevice();
            }

            Optional<DeviceEnrollment> approvedRequest = findOpenApproval(command.enrollmentId(), session,
                    EnrollmentState.WAITING_APPROVAL);
            if (approvedRequest.isEmpty() || !approvedRequest.get().hasApprovalInProgress()) {
                return new AuthorizeEnrollmentResult.Conflict();
            }
            DeviceEnrollment enrollment = approvedRequest.get();

            // Only the device that approved may collect the token.
            if (!primaryDeviceId.get().equals(enrollment.actorDeviceId())) {
                return new AuthorizeEnrollmentResult.Conflict();
            }

            MfaCheckRequest mfaCheckRequest = MfaCheckRequest.builder()
                    .mfaTransactionId(enrollment.mfaTransactionId())
                    .authOperationId(enrollment.id())
                    .purpose(enrollment.purpose())
                    .factors(FACE_AND_OTP)
                    .contextDigest(EnrollmentDigests.contextDigest(enrollment))
                    .build();
            CheckResult checkResult = mfaTransactionPort.check(mfaCheckRequest);

            return switch (checkResult) {
                case CheckResult.Pending() -> new AuthorizeEnrollmentResult.MfaPending();
                case CheckResult.Rejected() -> new AuthorizeEnrollmentResult.Rejected();
                case CheckResult.Failed() -> {
                    DeviceEnrollment failedEnrollment = enrollment.fail();
                    enrollmentRepository.saveIfCurrent(failedEnrollment);
                    yield new AuthorizeEnrollmentResult.MfaFailed();
                }
                case CheckResult.Expired() -> {
                    DeviceEnrollment expiredEnrollment = enrollment.expire();
                    enrollmentRepository.saveIfCurrent(expiredEnrollment);
                    yield new AuthorizeEnrollmentResult.MfaExpired();
                }
                case CheckResult.Passed(String receiptDigest) -> issueAuthorizationToken(enrollment, mfaCheckRequest);
            };
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new AuthorizeEnrollmentResult.Unavailable();
        }
    }

    /** The token is handed out once; Auth keeps its digest, its deadline and which factors the approver passed. */
    private AuthorizeEnrollmentResult issueAuthorizationToken(DeviceEnrollment enrollment, MfaCheckRequest mfaCheckRequest) {
        Instant now = clock.instant();

        String authorizationToken = authorizationTokenGenerator.next();
        String tokenDigest = EnrollmentDigests.digest(authorizationToken);
        Instant tokenExpiresAt = earlier(now.plus(enrollmentPolicy.approvalTokenLifetime()), enrollment.expiresAt());

        DeviceEnrollment authorizedEnrollment = enrollment.authorize(tokenDigest, tokenExpiresAt, mfaCheckRequest.factorClaim());
        Optional<DeviceEnrollment> savedEnrollment = enrollmentRepository.saveIfCurrent(authorizedEnrollment);
        if (savedEnrollment.isEmpty()) {
            return new AuthorizeEnrollmentResult.Conflict();
        }

        return new AuthorizeEnrollmentResult.Authorized(enrollment.id(), authorizationToken, tokenExpiresAt);
    }

    // ---- the new device again ----

    @Override
    public ClaimEnrollmentResult claim(ClaimEnrollmentCommand command) {
        try {
            Optional<StoredSession> restrictedSession = findRestrictedSession(command.token());
            if (restrictedSession.isEmpty()) {
                return new ClaimEnrollmentResult.SessionGone();
            }
            StoredSession storedSession = restrictedSession.get();
            Session session = storedSession.session();

            // The claim is bound to the session that made the request.
            Optional<DeviceEnrollment> request =
                    enrollmentRepository.findBySession(session.customerId(), session.deviceId(), session.id());
            boolean waitingForToken = request.isPresent()
                    && request.get().isApproval()
                    && request.get().state() == EnrollmentState.WAITING_AUTHORIZATION
                    && request.get().isOpen(clock.instant());
            if (!waitingForToken) {
                return new ClaimEnrollmentResult.Conflict();
            }
            DeviceEnrollment enrollment = request.get();

            if (enrollment.authorizationExpired(clock.instant())) {
                DeviceEnrollment expiredEnrollment = enrollment.expire();
                endRestrictedSession(storedSession, expiredEnrollment);
                return new ClaimEnrollmentResult.AuthorizationExpired();
            }

            // The attempt is counted before the token is compared, so a lost race cannot grant a free try.
            DeviceEnrollment enrollmentWithAttempt = enrollment.countClaimAttempt();
            Optional<DeviceEnrollment> savedEnrollment = enrollmentRepository.saveIfCurrent(enrollmentWithAttempt);
            if (savedEnrollment.isEmpty()) {
                return new ClaimEnrollmentResult.Conflict();
            }
            DeviceEnrollment countedEnrollment = savedEnrollment.get();

            String presentedDigest = EnrollmentDigests.digest(command.authorizationToken());
            boolean rightToken = EnrollmentDigests.sameDigest(countedEnrollment.authorizationTokenDigest(), presentedDigest);
            if (!rightToken) {
                return wrongToken(storedSession, countedEnrollment);
            }

            return commitTrust(command, storedSession, countedEnrollment);
        } catch (RepositoryUnavailableException failure) {
            return new ClaimEnrollmentResult.Unavailable();
        }
    }

    private ClaimEnrollmentResult wrongToken(StoredSession storedSession, DeviceEnrollment countedEnrollment) {
        if (countedEnrollment.claimAttemptsExhausted(enrollmentPolicy)) {
            DeviceEnrollment failedEnrollment = countedEnrollment.fail();
            endRestrictedSession(storedSession, failedEnrollment);
            return new ClaimEnrollmentResult.WrongAuthorization(NO_ATTEMPTS_LEFT);
        }
        int attemptsLeft = enrollmentPolicy.maxClaimAttempts() - countedEnrollment.authorizationAttempts();
        return new ClaimEnrollmentResult.WrongAuthorization(attemptsLeft);
    }

    private ClaimEnrollmentResult commitTrust(ClaimEnrollmentCommand command, StoredSession storedSession,
                                              DeviceEnrollment countedEnrollment) {
        Session restrictedSession = storedSession.session();

        // Only one claim may commit: the restricted session is consumed first.
        boolean sessionConsumed = sessionStore.deleteIfCurrent(storedSession.lookup(), restrictedSession);
        if (!sessionConsumed) {
            return new ClaimEnrollmentResult.Conflict();
        }

        DeviceEnrollment consumedEnrollment = countedEnrollment.consumeAuthorization(clock.instant());
        String correlationId = restrictedSession.id().toString();
        TrustedDevice trustedDevice = trustedDeviceService.confirmTrustByApproval(consumedEnrollment, correlationId);

        Session activeSession = Session.start(
                sessionIdGenerator.get(),
                trustedDevice.customerId(),
                trustedDevice.deviceId(),
                restrictedSession.channel(),
                clock.instant(),
                sessionPolicy);

        OpaqueToken token = opaqueTokenGenerator.next(activeSession.channel(), activeSession.id());
        String tokenEnvelope = tokenEnvelopeSealer.seal(command.tokenEncryptionKey(), token, activeSession);
        sessionStore.create(activeSession, token);

        return new ClaimEnrollmentResult.Trusted(
                tokenEnvelope,
                activeSession.idleExpiresAt(),
                activeSession.absoluteExpiresAt());
    }

    // ---- shared steps ----

    private Optional<StoredSession> findRestrictedSession(OpaqueToken token) {
        Instant now = clock.instant();
        return sessionStore.findByToken(token)
                .filter(stored -> stored.session().isLive(now))
                .filter(stored -> stored.session().status() == SessionStatus.NEED_TRUSTED_DEVICE)
                .filter(stored -> stored.session().deviceId() != null);
    }

    private Optional<StoredSession> findActiveSession(OpaqueToken token) {
        Instant now = clock.instant();
        return sessionStore.findByToken(token)
                .filter(stored -> stored.session().isFull(now))
                .filter(stored -> stored.session().deviceId() != null);
    }

    /** The caller's device row ID when that device is the customer's trusted primary on the channel. */
    private Optional<TrustedDeviceId> primaryDeviceIdOf(Session session) {
        return trustedDeviceService.primaryDeviceId(session.customerId(), session.channel(), session.deviceId());
    }

    private Optional<DeviceEnrollment> findOpenApproval(EnrollmentId enrollmentId, Session session,
                                                        EnrollmentState expectedState) {
        Instant now = clock.instant();
        return enrollmentRepository.findApproval(enrollmentId, session.customerId(), session.channel())
                .filter(DeviceEnrollment::isApproval)
                .filter(enrollment -> enrollment.isOpen(now))
                .filter(enrollment -> enrollment.state() == expectedState);
    }

    /** A terminal enrollment state is written first, then the restricted session is dropped. */
    private void endRestrictedSession(StoredSession storedSession, DeviceEnrollment terminalEnrollment) {
        enrollmentRepository.saveIfCurrent(terminalEnrollment);
        sessionStore.deleteIfCurrent(storedSession.lookup(), storedSession.session());
    }

    private static Optional<TrustedDevice> findById(List<TrustedDevice> devices, TrustedDeviceId deviceId) {
        return devices.stream()
                .filter(device -> device.id().equals(deviceId))
                .findFirst();
    }

    private static Instant earlier(Instant first, Instant second) {
        return first.isBefore(second) ? first : second;
    }
}
