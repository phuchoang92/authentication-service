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
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CheckResult;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CreateResult;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.model.MfaCheckRequest;
import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentRepository;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentTransactionStore;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.application.result.ApprovalStatusResult;
import com.vpbank.dcp.auth.application.result.ApproveEnrollmentResult;
import com.vpbank.dcp.auth.application.result.AuthorizeEnrollmentResult;
import com.vpbank.dcp.auth.application.result.ClaimEnrollmentResult;
import com.vpbank.dcp.auth.application.result.KnownDeviceSummary;
import com.vpbank.dcp.auth.application.result.ListPendingDevicesResult;
import com.vpbank.dcp.auth.application.result.PendingDeviceSummary;
import com.vpbank.dcp.auth.application.result.RequestApprovalResult;
import com.vpbank.dcp.auth.application.service.SessionService.IssuedSession;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.MfaFactor;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
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
 * The new device, on a restricted session, registers a PENDING row and an approval request. The
 * primary device, on its ACTIVE session, lists the requests, approves one (FACE + OTP at the MFA
 * service) and receives a one-time authorization token to show as a QR. The new device claims that
 * token from a restricted session; the trust commit then makes it trusted and primary, ends the
 * restricted session and issues a full ACTIVE one. Auth keeps only the token's digest.
 *
 * <p>Slice 11: the caller is the session the BFF admitted ({@link AdmittedSession}). Auth reads no session
 * to learn who calls; it checks only that the kind of session fits the route, and addresses the restricted
 * session by the asserted channel and session ID when it consumes or ends it. A request belongs to the
 * device, not to the restricted session that made it: one open request per device, which a later login of
 * the same device can poll and claim.
 */
@RequiredArgsConstructor
public final class DeviceApprovalService implements RequestApprovalUseCase, ApprovalStatusUseCase,
        ListPendingDevicesUseCase, ApproveEnrollmentUseCase, AuthorizeEnrollmentUseCase, ClaimEnrollmentUseCase {
    /** The approving device confirms with FACE and OTP (decision 2026-10-25). */
    private static final List<MfaFactor> FACE_AND_OTP = List.of(MfaFactor.FACE, MfaFactor.OTP);
    /** The last wrong token leaves no attempt; the enrollment is already failed when it is reported. */
    private static final int NO_ATTEMPTS_LEFT = 0;

    @NonNull private final SessionService sessionService;
    @NonNull private final EnrollmentRepository enrollmentRepository;
    @NonNull private final EnrollmentTransactionStore enrollmentTransactionStore;
    @NonNull private final TrustedDeviceRepository trustedDeviceRepository;
    @NonNull private final TrustedDeviceService trustedDeviceService;
    @NonNull private final MfaTransactionPort mfaTransactionPort;
    @NonNull private final AuthorizationTokenGenerator authorizationTokenGenerator;
    @NonNull private final Supplier<EnrollmentId> enrollmentIdGenerator;
    @NonNull private final EnrollmentPolicy enrollmentPolicy;
    @NonNull private final Clock clock;

    // ---- the new device ----

    @Override
    public RequestApprovalResult request(RequestApprovalCommand command) {
        try {
            AdmittedSession caller = command.admitted();
            if (!caller.restricted()) {
                return new RequestApprovalResult.Conflict();
            }

            // The primary enrollment (FACE on this device) already started on this session.
            boolean primaryEnrollmentInFlight = enrollmentTransactionStore
                    .find(caller.customerId(), caller.channel(), caller.deviceId())
                    .filter(transaction -> transaction.belongsTo(caller))
                    .isPresent();
            if (primaryEnrollmentInFlight) {
                return new RequestApprovalResult.Conflict();
            }

            // One open request per device: asking again, from this login or a later one, gets the same request.
            Optional<DeviceEnrollment> latestRequest = latestRequestOf(caller);
            boolean deviceAlreadyWaits = latestRequest.isPresent() && latestRequest.get().isOpen(clock.instant());
            if (deviceAlreadyWaits) {
                return new RequestApprovalResult.WaitingApproval(latestRequest.get().id(), latestRequest.get().expiresAt());
            }

            Optional<KnownDeviceSummary> knownDevice = trustedDeviceService.knownDevice(
                    caller.customerId(),
                    caller.channel(),
                    caller.deviceId());

            // An unknown installation must send both; a known live row keeps what Auth already stores.
            String devicePublicJwk = command.devicePublicJwk();
            DevicePlatform platform = command.platform();
            boolean unknownDeviceWithoutKey = knownDevice.isEmpty() && (devicePublicJwk == null || platform == null);
            if (unknownDeviceWithoutKey) {
                return new RequestApprovalResult.DeviceKeyRequired();
            }

            String correlationId = caller.sessionId().toString();
            Optional<TrustedDevice> targetDevice = trustedDeviceService.registerPendingDevice(
                    caller.customerId(),
                    caller.channel(),
                    caller.deviceId(),
                    platform,
                    devicePublicJwk,
                    enrollmentPolicy,
                    correlationId);
            if (targetDevice.isEmpty()) {
                return new RequestApprovalResult.TooManyPending();
            }

            // The request waits as long as its PENDING device row does; Auth no longer reads the session's deadline.
            Instant requestExpiresAt = clock.instant().plus(enrollmentPolicy.pendingWindow());
            DeviceEnrollment freshRequest = DeviceEnrollment.requestApproval(
                    enrollmentIdGenerator.get(),
                    caller.customerId(),
                    caller.channel(),
                    caller.deviceId(),
                    targetDevice.get().id(),
                    requestExpiresAt);
            DeviceEnrollment storedRequest = enrollmentRepository.create(freshRequest, caller.sessionId());

            // This session already made a request that is closed now (UQ_DE_CREATION): it cannot make another.
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
            AdmittedSession caller = command.admitted();
            if (!caller.restricted()) {
                return new ApprovalStatusResult.NoRequest();
            }

            Optional<DeviceEnrollment> request = latestRequestOf(caller);
            if (request.isEmpty()) {
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
            AdmittedSession caller = command.admitted();
            Optional<TrustedDeviceId> primaryDeviceId = primaryDeviceIdOf(caller);
            if (primaryDeviceId.isEmpty()) {
                return new ListPendingDevicesResult.NotPrimaryDevice();
            }

            Instant now = clock.instant();
            List<DeviceEnrollment> openApprovals =
                    enrollmentRepository.findOpenApprovals(caller.customerId(), caller.channel());
            List<TrustedDevice> liveDevices = trustedDeviceRepository.findLive(caller.customerId(), caller.channel());

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
            AdmittedSession caller = command.admitted();
            Optional<TrustedDeviceId> primaryDeviceId = primaryDeviceIdOf(caller);
            if (primaryDeviceId.isEmpty()) {
                return new ApproveEnrollmentResult.NotPrimaryDevice();
            }

            Optional<DeviceEnrollment> waitingRequest = findOpenApproval(command.enrollmentId(), caller,
                    EnrollmentState.WAITING_APPROVAL);
            if (waitingRequest.isEmpty() || waitingRequest.get().hasApprovalInProgress()) {
                return new ApproveEnrollmentResult.Conflict();
            }
            DeviceEnrollment enrollment = waitingRequest.get();

            MfaTransactionRequest mfaTransactionRequest = MfaTransactionRequest.builder()
                    .customerId(caller.customerId())
                    .channel(caller.channel())
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
            AdmittedSession caller = command.admitted();
            Optional<TrustedDeviceId> primaryDeviceId = primaryDeviceIdOf(caller);
            if (primaryDeviceId.isEmpty()) {
                return new AuthorizeEnrollmentResult.NotPrimaryDevice();
            }

            Optional<DeviceEnrollment> approvedRequest = findOpenApproval(command.enrollmentId(), caller,
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
                    .customerId(enrollment.customerId())
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
                case CheckResult.Passed(_) -> issueAuthorizationToken(enrollment, mfaCheckRequest);
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
            AdmittedSession caller = command.admitted();
            if (!caller.restricted()) {
                return new ClaimEnrollmentResult.Conflict();
            }
            SessionLookup restrictedSessionLookup = lookupOf(caller);

            // The claim is bound to the device that made the request, from any of its restricted sessions.
            Optional<DeviceEnrollment> request = latestRequestOf(caller);
            boolean waitingForToken = request.isPresent()
                    && request.get().state() == EnrollmentState.WAITING_AUTHORIZATION
                    && request.get().isOpen(clock.instant());
            if (!waitingForToken) {
                return new ClaimEnrollmentResult.Conflict();
            }
            DeviceEnrollment enrollment = request.get();

            if (enrollment.authorizationExpired(clock.instant())) {
                DeviceEnrollment expiredEnrollment = enrollment.expire();
                endRestrictedSession(restrictedSessionLookup, expiredEnrollment);
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
                return wrongToken(restrictedSessionLookup, countedEnrollment);
            }

            return commitTrust(command, caller, countedEnrollment);
        } catch (RepositoryUnavailableException failure) {
            return new ClaimEnrollmentResult.Unavailable();
        }
    }

    private ClaimEnrollmentResult wrongToken(SessionLookup restrictedSessionLookup, DeviceEnrollment countedEnrollment) {
        if (countedEnrollment.claimAttemptsExhausted(enrollmentPolicy)) {
            DeviceEnrollment failedEnrollment = countedEnrollment.fail();
            endRestrictedSession(restrictedSessionLookup, failedEnrollment);
            return new ClaimEnrollmentResult.WrongAuthorization(NO_ATTEMPTS_LEFT);
        }
        int attemptsLeft = enrollmentPolicy.maxClaimAttempts() - countedEnrollment.authorizationAttempts();
        return new ClaimEnrollmentResult.WrongAuthorization(attemptsLeft);
    }

    private ClaimEnrollmentResult commitTrust(ClaimEnrollmentCommand command, AdmittedSession caller,
                                              DeviceEnrollment countedEnrollment) {
        // Only one claim may commit: the restricted session is consumed first.
        boolean sessionConsumed = sessionService.consume(lookupOf(caller));
        if (!sessionConsumed) {
            return new ClaimEnrollmentResult.Conflict();
        }

        DeviceEnrollment consumedEnrollment = countedEnrollment.consumeAuthorization(clock.instant());
        String correlationId = caller.sessionId().toString();
        TrustedDevice trustedDevice = trustedDeviceService.confirmTrustByApproval(consumedEnrollment, correlationId);

        IssuedSession activeSession = sessionService.issueActive(
                sessionService.newSessionId(),
                trustedDevice.customerId(),
                trustedDevice.deviceId(),
                caller.channel(),
                command.tokenEncryptionKey());

        return new ClaimEnrollmentResult.Trusted(
                activeSession.tokenEnvelope(),
                activeSession.session().idleExpiresAt(),
                activeSession.session().absoluteExpiresAt());
    }

    // ---- shared steps ----

    /** The caller device's newest approval request on the channel (slice 11: bound to the device, not the session). */
    private Optional<DeviceEnrollment> latestRequestOf(AdmittedSession caller) {
        return enrollmentRepository.findLatestApproval(caller.customerId(), caller.channel(), caller.deviceId());
    }

    /** Where the caller's session lives; the assertion names it, so nothing is read to find it. */
    private static SessionLookup lookupOf(AdmittedSession caller) {
        return new SessionLookup(caller.channel(), caller.sessionId());
    }

    /**
     * The caller's device row ID when the caller is on a full ACTIVE session and that device is the
     * customer's trusted primary on the channel. A restricted session never approves.
     */
    private Optional<TrustedDeviceId> primaryDeviceIdOf(AdmittedSession caller) {
        if (!caller.full()) {
            return Optional.empty();
        }
        return trustedDeviceService.primaryDeviceId(caller.customerId(), caller.channel(), caller.deviceId());
    }

    private Optional<DeviceEnrollment> findOpenApproval(EnrollmentId enrollmentId, AdmittedSession caller,
                                                        EnrollmentState expectedState) {
        Instant now = clock.instant();
        return enrollmentRepository.findApproval(enrollmentId, caller.customerId(), caller.channel())
                .filter(DeviceEnrollment::isApproval)
                .filter(enrollment -> enrollment.isOpen(now))
                .filter(enrollment -> enrollment.state() == expectedState);
    }

    /** A terminal enrollment state is written first, then the restricted session is dropped. */
    private void endRestrictedSession(SessionLookup restrictedSessionLookup, DeviceEnrollment terminalEnrollment) {
        enrollmentRepository.saveIfCurrent(terminalEnrollment);
        sessionService.end(restrictedSessionLookup);
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
