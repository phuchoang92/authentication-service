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
import com.vpbank.dcp.auth.application.port.out.gateway.ChallengeSealer;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CheckResult;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CreateResult;
import com.vpbank.dcp.auth.application.port.out.gateway.ServerKeyPairGenerator;
import com.vpbank.dcp.auth.application.port.out.model.MfaCheckRequest;
import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import com.vpbank.dcp.auth.application.port.out.model.OpenedChallenge;
import com.vpbank.dcp.auth.application.port.out.model.ServerKeyPair;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.port.out.repository.EnrollmentTransactionStore;
import com.vpbank.dcp.auth.application.result.ConfirmEnrollmentResult;
import com.vpbank.dcp.auth.application.result.InitEnrollmentResult;
import com.vpbank.dcp.auth.application.result.KnownDeviceSummary;
import com.vpbank.dcp.auth.application.result.VerifyEnrollmentResult;
import com.vpbank.dcp.auth.application.service.SessionService.IssuedSession;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.MfaFactor;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Clock;
import java.time.Duration;
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
 * session and issues a full ACTIVE one. Steps run once each, in order.
 *
 * <p>Slice 11: the caller is the session the BFF admitted ({@link AdmittedSession}); only a restricted one may
 * run these steps, and no session is read. The steps share an {@link EnrollmentTransaction} in the cache (Ksrv,
 * challenge digest, attempts, MFA transaction), one per device, bound to the restricted session that ran init.
 * Nothing is written to SQL before the commit: the enrollment row is inserted, already COMPLETED, with the trust.
 * A failure or an MFA expiry removes the transaction and ends the restricted session.
 */
@RequiredArgsConstructor
public final class DeviceEnrollmentService
        implements InitEnrollmentUseCase, VerifyEnrollmentUseCase, ConfirmEnrollmentUseCase {
    /**
     * The last wrong answer leaves no attempt; the transaction is already gone when it is reported.
     */
    private static final int NO_ATTEMPTS_LEFT = 0;
    /** The primary enrollment asks the customer for FACE alone (DD 20 §4). */
    private static final List<MfaFactor> FACE_ONLY = List.of(MfaFactor.FACE);
    private static final EnrollmentPurpose PRIMARY_ENROLLMENT = EnrollmentPurpose.TRUST_DEVICE;

    @NonNull
    private final SessionService sessionService;
    @NonNull
    private final EnrollmentTransactionStore enrollmentTransactionStore;
    @NonNull
    private final TrustedDeviceService trustedDeviceService;
    @NonNull
    private final MfaTransactionPort mfaTransactionPort;
    @NonNull
    private final ServerKeyPairGenerator serverKeyPairGenerator;
    @NonNull
    private final ChallengeSealer challengeSealer;
    @NonNull
    private final Supplier<EnrollmentId> enrollmentIdGenerator;
    @NonNull
    private final EnrollmentPolicy enrollmentPolicy;
    /** How long a transaction may wait for confirm: the lifetime of the restricted session that runs it. */
    @NonNull
    private final Duration enrollmentLifetime;
    @NonNull
    private final Clock clock;

    @Override
    public InitEnrollmentResult init(InitEnrollmentCommand command) {
        try {
            AdmittedSession caller = command.admitted();
            if (!caller.restricted()) {
                return new InitEnrollmentResult.Conflict();
            }

            // init runs once per restricted session; a new login on the same device starts over.
            Optional<EnrollmentTransaction> earlierTransaction = enrollmentTransactionStore.find(
                    caller.customerId(),
                    caller.channel(),
                    caller.deviceId());
            if (earlierTransaction.isPresent()) {
                if (earlierTransaction.get().belongsTo(caller)) {
                    return new InitEnrollmentResult.Conflict();
                }
                boolean supersededTheEarlierLogin = enrollmentTransactionStore.deleteIfCurrent(earlierTransaction.get());
                if (!supersededTheEarlierLogin) {
                    return new InitEnrollmentResult.Conflict();
                }
            }

            Optional<KnownDeviceSummary> knownDevice = trustedDeviceService.knownDevice(
                    caller.customerId(),
                    caller.channel(),
                    caller.deviceId());

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

            ServerKeyPair serverKeyPair = serverKeyPairGenerator.next();
            TrustedDeviceId targetDeviceId = knownDevice.map(KnownDeviceSummary::id).orElse(null);
            Instant expiresAt = clock.instant().plus(enrollmentLifetime);
            EnrollmentTransaction freshTransaction = EnrollmentTransaction.keyExchange(
                    enrollmentId,
                    caller,
                    targetDeviceId,
                    devicePublicJwk,
                    platform,
                    serverKeyPair.publicJwk(),
                    serverKeyPair.privateJwk(),
                    EnrollmentDigests.digest(challenge),
                    expiresAt);

            // A racing init of the same device got there first.
            boolean created = enrollmentTransactionStore.createIfAbsent(freshTransaction);
            if (!created) {
                return new InitEnrollmentResult.Conflict();
            }

            return new InitEnrollmentResult.KeyExchange(
                    enrollmentId,
                    serverKeyPair.publicJwk(),
                    sealedChallenge,
                    expiresAt);
        } catch (RepositoryUnavailableException failure) {
            return new InitEnrollmentResult.Unavailable();
        }
    }

    @Override
    public VerifyEnrollmentResult verify(VerifyEnrollmentCommand command) {
        try {
            AdmittedSession caller = command.admitted();
            if (!caller.restricted()) {
                return new VerifyEnrollmentResult.Conflict();
            }

            Optional<EnrollmentTransaction> openTransaction = findOpenTransaction(caller, EnrollmentState.KEY_EXCHANGE);
            if (openTransaction.isEmpty()) {
                return new VerifyEnrollmentResult.Conflict();
            }

            // The attempt is counted before the answer is checked, so a lost race cannot grant a free try.
            EnrollmentTransaction transactionWithAttempt = openTransaction.get().countVerifyAttempt();
            Optional<EnrollmentTransaction> savedTransaction = enrollmentTransactionStore.saveIfCurrent(transactionWithAttempt);
            if (savedTransaction.isEmpty()) {
                return new VerifyEnrollmentResult.Conflict();
            }
            EnrollmentTransaction transaction = savedTransaction.get();

            Optional<OpenedChallenge> openedResponse = challengeSealer.openResponse(
                    transaction.serverPrivateJwk(),
                    command.challengeResponse());
            boolean keyProven = openedResponse.isPresent()
                    && answersThisEnrollment(openedResponse.get(), transaction);
            if (!keyProven) {
                return wrongChallenge(caller, transaction);
            }

            MfaTransactionRequest mfaTransactionRequest = MfaTransactionRequest.builder()
                    .customerId(transaction.customerId())
                    .channel(transaction.channel())
                    .authOperationId(transaction.id())
                    .purpose(PRIMARY_ENROLLMENT)
                    .factors(FACE_ONLY)
                    .notAfter(transaction.expiresAt())
                    .contextDigest(EnrollmentDigests.contextDigest(transaction))
                    .build();
            CreateResult createResult = mfaTransactionPort.create(mfaTransactionRequest);

            return switch (createResult) {
                case CreateResult.NoUsableFactor() -> {
                    endEnrollment(caller, transaction);
                    yield new VerifyEnrollmentResult.NoUsableFactor();
                }
                case CreateResult.Created(String mfaTransactionId, Instant mfaExpiresAt) ->
                        recordMfaRequired(transaction, mfaTransactionId, mfaExpiresAt);
            };
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new VerifyEnrollmentResult.Unavailable();
        }
    }

    private VerifyEnrollmentResult wrongChallenge(AdmittedSession caller, EnrollmentTransaction transaction) {
        if (transaction.attemptsExhausted(enrollmentPolicy)) {
            endEnrollment(caller, transaction);
            return new VerifyEnrollmentResult.WrongChallenge(NO_ATTEMPTS_LEFT);
        }
        int attemptsLeft = enrollmentPolicy.maxVerifyAttempts() - transaction.verifyAttempts();
        return new VerifyEnrollmentResult.WrongChallenge(attemptsLeft);
    }

    private VerifyEnrollmentResult recordMfaRequired(EnrollmentTransaction transaction, String mfaTransactionId,
                                                     Instant mfaExpiresAt) {
        EnrollmentTransaction mfaRequiredTransaction = transaction.markMfaRequired(mfaTransactionId);
        Optional<EnrollmentTransaction> savedTransaction = enrollmentTransactionStore.saveIfCurrent(mfaRequiredTransaction);
        if (savedTransaction.isEmpty()) {
            return new VerifyEnrollmentResult.Conflict();
        }

        // The app gets the earlier of the two deadlines: the MFA transaction or the enrollment itself.
        Instant expiresAt = transaction.expiresAt();
        if (mfaExpiresAt.isBefore(transaction.expiresAt())) {
            expiresAt = mfaExpiresAt;
        }
        return new VerifyEnrollmentResult.MfaRequired(mfaTransactionId, expiresAt);
    }

    @Override
    public ConfirmEnrollmentResult confirm(ConfirmEnrollmentCommand command) {
        try {
            AdmittedSession caller = command.admitted();
            if (!caller.restricted()) {
                return new ConfirmEnrollmentResult.Conflict();
            }

            Optional<EnrollmentTransaction> openTransaction = findOpenTransaction(caller, EnrollmentState.MFA_REQUIRED);
            if (openTransaction.isEmpty()) {
                return new ConfirmEnrollmentResult.Conflict();
            }
            EnrollmentTransaction transaction = openTransaction.get();

            MfaCheckRequest mfaCheckRequest = MfaCheckRequest.builder()
                    .mfaTransactionId(transaction.mfaTransactionId())
                    .customerId(transaction.customerId())
                    .authOperationId(transaction.id())
                    .purpose(PRIMARY_ENROLLMENT)
                    .factors(FACE_ONLY)
                    .contextDigest(EnrollmentDigests.contextDigest(transaction))
                    .build();
            CheckResult checkResult = mfaTransactionPort.check(mfaCheckRequest);

            return switch (checkResult) {
                case CheckResult.Pending() -> new ConfirmEnrollmentResult.MfaPending();
                case CheckResult.Rejected() -> new ConfirmEnrollmentResult.Rejected();
                case CheckResult.Failed() -> {
                    endEnrollment(caller, transaction);
                    yield new ConfirmEnrollmentResult.MfaFailed();
                }
                case CheckResult.Expired() -> {
                    endEnrollment(caller, transaction);
                    yield new ConfirmEnrollmentResult.MfaExpired();
                }
                case CheckResult.Passed(String receiptDigest) ->
                        commitTrust(command, caller, transaction, receiptDigest);
            };
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new ConfirmEnrollmentResult.Unavailable();
        }
    }

    private ConfirmEnrollmentResult commitTrust(ConfirmEnrollmentCommand command, AdmittedSession caller,
                                                EnrollmentTransaction transaction, String receiptDigest) {
        // Only one confirm may commit: the transaction is removed first, compare-and-set on its version.
        boolean transactionClaimed = enrollmentTransactionStore.deleteIfCurrent(transaction);
        if (!transactionClaimed) {
            return new ConfirmEnrollmentResult.Conflict();
        }

        // The restricted session ends with its enrollment; one that is already gone (a logout) commits nothing.
        boolean sessionConsumed = sessionService.consume(restrictedSessionOf(caller));
        if (!sessionConsumed) {
            return new ConfirmEnrollmentResult.Conflict();
        }

        DeviceEnrollment passedEnrollment = DeviceEnrollment.fromTransaction(transaction);
        String correlationId = caller.sessionId().toString();
        TrustedDevice trustedDevice = trustedDeviceService.confirmTrust(
                passedEnrollment,
                caller.sessionId(),
                transaction.platform(),
                transaction.devicePublicJwk(),
                receiptDigest,
                correlationId);

        IssuedSession activeSession = sessionService.issueActive(
                sessionService.newSessionId(),
                trustedDevice.customerId(),
                trustedDevice.deviceId(),
                caller.channel(),
                command.tokenEncryptionKey());

        return new ConfirmEnrollmentResult.Trusted(
                activeSession.tokenEnvelope(),
                activeSession.session().idleExpiresAt(),
                activeSession.session().absoluteExpiresAt());
    }

    /** The device's transaction, when this restricted session started it, it is still open and at this step. */
    private Optional<EnrollmentTransaction> findOpenTransaction(AdmittedSession caller, EnrollmentState expectedState) {
        Instant now = clock.instant();
        return enrollmentTransactionStore.find(caller.customerId(), caller.channel(), caller.deviceId())
                .filter(transaction -> transaction.belongsTo(caller))
                .filter(transaction -> transaction.isOpen(now))
                .filter(transaction -> transaction.state() == expectedState);
    }

    /** A failed or expired enrollment leaves nothing behind: the transaction goes, then the restricted session. */
    private void endEnrollment(AdmittedSession caller, EnrollmentTransaction transaction) {
        enrollmentTransactionStore.deleteIfCurrent(transaction);
        sessionService.end(restrictedSessionOf(caller));
    }

    private static SessionLookup restrictedSessionOf(AdmittedSession caller) {
        return new SessionLookup(caller.channel(), caller.sessionId());
    }

    /**
     * The response must echo this enrollment and the exact challenge; compared in constant time.
     */
    private static boolean answersThisEnrollment(OpenedChallenge openedResponse, EnrollmentTransaction transaction) {
        if (!openedResponse.enrollmentId().equals(transaction.id())) {
            return false;
        }
        String answeredDigest = EnrollmentDigests.digest(openedResponse.challenge());
        return EnrollmentDigests.sameDigest(transaction.challengeDigest(), answeredDigest);
    }
}
