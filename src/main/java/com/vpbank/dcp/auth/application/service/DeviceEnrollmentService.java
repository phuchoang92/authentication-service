package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.ConfirmEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.InitEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.VerifyEnrollmentCommand;
import com.vpbank.dcp.auth.application.port.in.ConfirmEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.InitEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.VerifyEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.InvalidEncryptionKeyException;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.*;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CheckResult;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CreateResult;
import com.vpbank.dcp.auth.application.port.out.model.MfaCheckRequest;
import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import com.vpbank.dcp.auth.application.port.out.model.OpenedChallenge;
import com.vpbank.dcp.auth.application.port.out.model.ServerKeyPair;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentRepository;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.application.result.ConfirmEnrollmentResult;
import com.vpbank.dcp.auth.application.result.InitEnrollmentResult;
import com.vpbank.dcp.auth.application.result.KnownDeviceSummary;
import com.vpbank.dcp.auth.application.result.VerifyEnrollmentResult;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.MfaFactor;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.*;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Device trust from a restricted session (DD 20 §4): init hands the app Ksrv and a challenge sealed
 * to the device key; verify proves the key and opens a FACE transaction at MFA; confirm reads the
 * MFA outcome and, on PASSED, lets {@link TrustedDeviceService} commit the trust, ends the restricted
 * session and issues a full ACTIVE one. Steps run once each, in order; the restricted session
 * carries the context (Ksrv private key, challenge digest), never SQL.
 */
@RequiredArgsConstructor
public final class DeviceEnrollmentService
        implements InitEnrollmentUseCase, VerifyEnrollmentUseCase, ConfirmEnrollmentUseCase {
    /**
     * The last wrong answer leaves no attempt; the enrollment is already failed when it is reported.
     */
    private static final int NO_ATTEMPTS_LEFT = 0;
    /** The primary enrollment asks the customer for FACE alone (DD 20 §4). */
    private static final List<MfaFactor> FACE_ONLY = List.of(MfaFactor.FACE);

    @NonNull
    private final SessionStore sessionStore;
    @NonNull
    private final EnrollmentRepository enrollmentRepository;
    @NonNull
    private final TrustedDeviceService trustedDeviceService;
    @NonNull
    private final MfaTransactionPort mfaTransactionPort;
    @NonNull
    private final ServerKeyPairGenerator serverKeyPairGenerator;
    @NonNull
    private final ChallengeSealer challengeSealer;
    @NonNull
    private final TokenEnvelopeSealer tokenEnvelopeSealer;
    @NonNull
    private final OpaqueTokenGenerator opaqueTokenGenerator;
    @NonNull
    private final Supplier<EnrollmentId> enrollmentIdGenerator;
    @NonNull
    private final Supplier<SessionId> sessionIdGenerator;
    @NonNull
    private final EnrollmentPolicy enrollmentPolicy;
    @NonNull
    private final SessionPolicy sessionPolicy;
    @NonNull
    private final Clock clock;

    @Override
    public InitEnrollmentResult init(InitEnrollmentCommand command) {
        try {
            Optional<StoredSession> restrictedSession = findRestrictedSession(command.token());
            if (restrictedSession.isEmpty()) {
                return new InitEnrollmentResult.SessionGone();
            }
            StoredSession storedSession = restrictedSession.get();
            Session session = storedSession.session();

            // init runs once per restricted session
            if (session.enrollment() != null) {
                return new InitEnrollmentResult.Conflict();
            }

            Optional<KnownDeviceSummary> knownDevice = trustedDeviceService.knownDevice(
                    session.customerId(),
                    session.channel(),
                    session.deviceId());

            // A known device may keep its stored key and platform; a new device must send both.
            String devicePublicJwk = command.devicePublicJwk();
            if (devicePublicJwk == null) {
                devicePublicJwk = knownDevice.map(KnownDeviceSummary::publicKey).orElse(null);
            }
            DevicePlatform platform = command.platform();
            if (platform == null) {
                platform = knownDevice.map(KnownDeviceSummary::platform).orElse(null);
            }
            if (devicePublicJwk == null || platform == null) {
                return new InitEnrollmentResult.DeviceKeyRequired();
            }

            EnrollmentId enrollmentId = enrollmentIdGenerator.get();
            byte[] challenge = challengeSealer.newChallenge();

            String sealedChallenge;
            try {
                sealedChallenge = challengeSealer.sealChallenge(devicePublicJwk, enrollmentId, challenge);
            } catch (InvalidEncryptionKeyException badKey) {
                return new InitEnrollmentResult.DeviceKeyRequired();
            }

            TrustedDeviceId targetDeviceId = knownDevice.map(KnownDeviceSummary::id).orElse(null);
            DeviceEnrollment freshEnrollment = DeviceEnrollment.start(
                    enrollmentId,
                    session.customerId(),
                    session.channel(),
                    session.deviceId(),
                    targetDeviceId,
                    session.absoluteExpiresAt());
            DeviceEnrollment storedEnrollment = enrollmentRepository.create(freshEnrollment, session.id());

            // A retried init may find the enrollment of this session already past this step.
            boolean isThisFreshEnrollment = storedEnrollment.id().equals(enrollmentId)
                    && storedEnrollment.state() == EnrollmentState.KEY_EXCHANGE;
            if (!isThisFreshEnrollment) {
                return new InitEnrollmentResult.Conflict();
            }

            ServerKeyPair serverKeyPair = serverKeyPairGenerator.next();
            EnrollmentContext enrollmentContext = EnrollmentContext.builder()
                    .enrollmentId(enrollmentId)
                    .devicePublicJwk(devicePublicJwk)
                    .platform(platform)
                    .serverPublicJwk(serverKeyPair.publicJwk())
                    .serverPrivateJwk(serverKeyPair.privateJwk())
                    .challengeDigest(EnrollmentDigests.digest(challenge))
                    .build();

            Session sessionWithEnrollment = session.withEnrollment(enrollmentContext);
            Optional<Session> savedSession = sessionStore.saveIfCurrent(storedSession.lookup(), sessionWithEnrollment);
            if (savedSession.isEmpty()) {
                return new InitEnrollmentResult.Conflict();
            }

            return new InitEnrollmentResult.KeyExchange(
                    enrollmentId,
                    serverKeyPair.publicJwk(),
                    sealedChallenge,
                    storedEnrollment.expiresAt());
        } catch (RepositoryUnavailableException failure) {
            return new InitEnrollmentResult.Unavailable();
        }
    }

    @Override
    public VerifyEnrollmentResult verify(VerifyEnrollmentCommand command) {
        try {
            Optional<StoredSession> restrictedSession = findRestrictedSession(command.token());
            if (restrictedSession.isEmpty()) {
                return new VerifyEnrollmentResult.SessionGone();
            }
            StoredSession storedSession = restrictedSession.get();
            Session session = storedSession.session();

            EnrollmentContext enrollmentContext = session.enrollment();
            if (enrollmentContext == null || enrollmentContext.keyProven()) {
                return new VerifyEnrollmentResult.Conflict();
            }

            Optional<DeviceEnrollment> openEnrollment = findOpenEnrollment(
                    enrollmentContext.enrollmentId(),
                    session,
                    EnrollmentState.KEY_EXCHANGE);
            if (openEnrollment.isEmpty()) {
                return new VerifyEnrollmentResult.Conflict();
            }

            // The attempt is counted before the answer is checked, so a lost race cannot grant a free try.
            DeviceEnrollment enrollmentWithAttempt = openEnrollment.get().countAttempt();
            Optional<DeviceEnrollment> savedEnrollment = enrollmentRepository.saveIfCurrent(enrollmentWithAttempt);
            if (savedEnrollment.isEmpty()) {
                return new VerifyEnrollmentResult.Conflict();
            }
            DeviceEnrollment enrollment = savedEnrollment.get();

            Optional<OpenedChallenge> openedResponse = challengeSealer.openResponse(
                    enrollmentContext.serverPrivateJwk(),
                    command.challengeResponse());
            boolean keyProven = openedResponse.isPresent()
                    && answersThisEnrollment(openedResponse.get(), enrollment, enrollmentContext);
            if (!keyProven) {
                return wrongChallenge(storedSession, enrollment);
            }

            MfaTransactionRequest mfaTransactionRequest = MfaTransactionRequest.builder()
                    .customerId(session.customerId())
                    .channel(session.channel())
                    .authOperationId(enrollment.id())
                    .purpose(enrollment.purpose())
                    .factors(FACE_ONLY)
                    .notAfter(enrollment.expiresAt())
                    .contextDigest(EnrollmentDigests.contextDigest(enrollment))
                    .build();
            CreateResult createResult = mfaTransactionPort.create(mfaTransactionRequest);

            return switch (createResult) {
                case CreateResult.NoUsableFactor() -> {
                    DeviceEnrollment failedEnrollment = enrollment.fail();
                    endRestrictedSession(storedSession, failedEnrollment);
                    yield new VerifyEnrollmentResult.NoUsableFactor();
                }
                case CreateResult.Created(String mfaTransactionId, Instant mfaExpiresAt) ->
                        recordMfaRequired(storedSession, enrollment, enrollmentContext, mfaTransactionId, mfaExpiresAt);
            };
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new VerifyEnrollmentResult.Unavailable();
        }
    }

    private VerifyEnrollmentResult wrongChallenge(StoredSession storedSession, DeviceEnrollment enrollment) {
        if (enrollment.attemptsExhausted(enrollmentPolicy)) {
            DeviceEnrollment failedEnrollment = enrollment.fail();
            endRestrictedSession(storedSession, failedEnrollment);
            return new VerifyEnrollmentResult.WrongChallenge(NO_ATTEMPTS_LEFT);
        }
        int attemptsLeft = enrollmentPolicy.maxVerifyAttempts() - enrollment.verifyAttempts();
        return new VerifyEnrollmentResult.WrongChallenge(attemptsLeft);
    }

    private VerifyEnrollmentResult recordMfaRequired(StoredSession storedSession, DeviceEnrollment enrollment,
                                                     EnrollmentContext enrollmentContext, String mfaTransactionId,
                                                     Instant mfaExpiresAt) {
        DeviceEnrollment mfaRequiredEnrollment = enrollment.markMfaRequired(mfaTransactionId);
        Optional<DeviceEnrollment> savedEnrollment = enrollmentRepository.saveIfCurrent(mfaRequiredEnrollment);
        if (savedEnrollment.isEmpty()) {
            return new VerifyEnrollmentResult.Conflict();
        }

        Session sessionWithProvenKey = storedSession.session().withEnrollment(enrollmentContext.proven());
        Optional<Session> savedSession = sessionStore.saveIfCurrent(storedSession.lookup(), sessionWithProvenKey);
        if (savedSession.isEmpty()) {
            return new VerifyEnrollmentResult.Conflict();
        }

        // The app gets the earlier of the two deadlines: the MFA transaction or the enrollment itself.
        Instant expiresAt = enrollment.expiresAt();
        if (mfaExpiresAt.isBefore(enrollment.expiresAt())) {
            expiresAt = mfaExpiresAt;
        }
        return new VerifyEnrollmentResult.MfaRequired(mfaTransactionId, expiresAt);
    }

    @Override
    public ConfirmEnrollmentResult confirm(ConfirmEnrollmentCommand command) {
        try {
            Optional<StoredSession> restrictedSession = findRestrictedSession(command.token());
            if (restrictedSession.isEmpty()) {
                return new ConfirmEnrollmentResult.SessionGone();
            }
            StoredSession storedSession = restrictedSession.get();
            Session session = storedSession.session();

            EnrollmentContext enrollmentContext = session.enrollment();
            if (enrollmentContext == null || !enrollmentContext.keyProven()) {
                return new ConfirmEnrollmentResult.Conflict();
            }

            Optional<DeviceEnrollment> openEnrollment = findOpenEnrollment(
                    enrollmentContext.enrollmentId(),
                    session,
                    EnrollmentState.MFA_REQUIRED);
            if (openEnrollment.isEmpty()) {
                return new ConfirmEnrollmentResult.Conflict();
            }
            DeviceEnrollment enrollment = openEnrollment.get();

            MfaCheckRequest mfaCheckRequest = MfaCheckRequest.builder()
                    .mfaTransactionId(enrollment.mfaTransactionId())
                    .authOperationId(enrollment.id())
                    .purpose(enrollment.purpose())
                    .factors(FACE_ONLY)
                    .contextDigest(EnrollmentDigests.contextDigest(enrollment))
                    .build();
            CheckResult checkResult = mfaTransactionPort.check(mfaCheckRequest);

            return switch (checkResult) {
                case CheckResult.Pending() -> new ConfirmEnrollmentResult.MfaPending();
                case CheckResult.Rejected() -> new ConfirmEnrollmentResult.Rejected();
                case CheckResult.Failed() -> {
                    DeviceEnrollment failedEnrollment = enrollment.fail();
                    endRestrictedSession(storedSession, failedEnrollment);
                    yield new ConfirmEnrollmentResult.MfaFailed();
                }
                case CheckResult.Expired() -> {
                    DeviceEnrollment expiredEnrollment = enrollment.expire();
                    endRestrictedSession(storedSession, expiredEnrollment);
                    yield new ConfirmEnrollmentResult.MfaExpired();
                }
                case CheckResult.Passed(String receiptDigest) ->
                        commitTrust(command, storedSession, enrollment, enrollmentContext, receiptDigest);
            };
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new ConfirmEnrollmentResult.Unavailable();
        }
    }

    private ConfirmEnrollmentResult commitTrust(ConfirmEnrollmentCommand command, StoredSession storedSession,
                                                DeviceEnrollment enrollment, EnrollmentContext enrollmentContext,
                                                String receiptDigest) {
        Session restrictedSession = storedSession.session();

        // Only one confirm may commit: the restricted session is consumed first.
        boolean sessionConsumed = sessionStore.deleteIfCurrent(storedSession.lookup(), restrictedSession);
        if (!sessionConsumed) {
            return new ConfirmEnrollmentResult.Conflict();
        }

        String correlationId = restrictedSession.id().toString();
        TrustedDevice trustedDevice = trustedDeviceService.confirmTrust(
                enrollment,
                enrollmentContext.platform(),
                enrollmentContext.devicePublicJwk(),
                receiptDigest,
                correlationId);

        Session activeSession = Session.start(
                sessionIdGenerator.get(),
                trustedDevice.customerId(),
                trustedDevice.deviceId(),
                restrictedSession.channel(),
                clock.instant(),
                sessionPolicy);

        OpaqueToken token = opaqueTokenGenerator.next();
        String tokenEnvelope = tokenEnvelopeSealer.seal(command.tokenEncryptionKey(), token, activeSession);
        sessionStore.create(activeSession, token);

        return new ConfirmEnrollmentResult.Trusted(
                tokenEnvelope,
                activeSession.idleExpiresAt(),
                activeSession.absoluteExpiresAt());
    }

    private Optional<StoredSession> findRestrictedSession(OpaqueToken token) {
        Instant now = clock.instant();
        return sessionStore.findByToken(token)
                .filter(stored -> stored.session().isLive(now))
                .filter(stored -> stored.session().status() == SessionStatus.NEED_TRUSTED_DEVICE);
    }

    private Optional<DeviceEnrollment> findOpenEnrollment(EnrollmentId enrollmentId, Session session,
                                                          EnrollmentState expectedState) {
        Instant now = clock.instant();
        return enrollmentRepository.find(enrollmentId, session.customerId(), session.deviceId())
                .filter(enrollment -> enrollment.isOpen(now))
                .filter(enrollment -> enrollment.state() == expectedState)
                .filter(enrollment -> enrollment.deviceId().equals(session.deviceId()));
    }

    /**
     * A terminal enrollment state is written first, then the restricted session is dropped.
     */
    private void endRestrictedSession(StoredSession storedSession, DeviceEnrollment terminalEnrollment) {
        enrollmentRepository.saveIfCurrent(terminalEnrollment);
        sessionStore.deleteIfCurrent(storedSession.lookup(), storedSession.session());
    }

    /**
     * The response must echo this enrollment and the exact challenge; compared in constant time.
     */
    private static boolean answersThisEnrollment(OpenedChallenge openedResponse, DeviceEnrollment enrollment,
                                                 EnrollmentContext enrollmentContext) {
        if (!openedResponse.enrollmentId().equals(enrollment.id())) {
            return false;
        }
        String answeredDigest = EnrollmentDigests.digest(openedResponse.challenge());
        return EnrollmentDigests.sameDigest(enrollmentContext.challengeDigest(), answeredDigest);
    }
}
