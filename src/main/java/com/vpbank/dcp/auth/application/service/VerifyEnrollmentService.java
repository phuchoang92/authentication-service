package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.VerifyEnrollmentCommand;
import com.vpbank.dcp.auth.application.port.in.VerifyEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.ChallengeSealer;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CreateResult;
import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.OpenedChallenge;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.result.VerifyEnrollmentResult;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import java.time.Instant;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Step 2 of a new device trusting itself (DD 20 §4): checks the device opened init's challenge with its key, then
 * asks the MFA service for a FACE check bound to this enrollment. Each answer counts as an attempt; the last wrong
 * one, or no usable factor, removes the transaction and ends the restricted session.
 */
@RequiredArgsConstructor
public final class VerifyEnrollmentService implements VerifyEnrollmentUseCase {
    /** The last wrong answer leaves no attempt; the transaction is already gone when it is reported. */
    private static final int NO_ATTEMPTS_LEFT = 0;

    @NonNull
    private final SessionService sessionService;
    @NonNull
    private final EnrollmentTransactions enrollmentTransactions;
    @NonNull
    private final ChallengeSealer challengeSealer;
    @NonNull
    private final MfaTransactionPort mfaTransactionPort;
    @NonNull
    private final EnrollmentPolicy enrollmentPolicy;

    @Override
    public VerifyEnrollmentResult verify(VerifyEnrollmentCommand command) {
        AdmittedSession newDeviceSession = command.admitted();
        if (!newDeviceSession.restricted()) {
            return new VerifyEnrollmentResult.Conflict();
        }
        try {
            Optional<CacheTransaction<EnrollmentTransaction>> counted = countVerifyAttempt(newDeviceSession);
            if (counted.isEmpty()) {
                return new VerifyEnrollmentResult.Conflict();
            }
            CacheTransaction<EnrollmentTransaction> transaction = counted.get();
            if (!provesDeviceKey(transaction.payload(), command.challengeResponse())) {
                return wrongChallenge(newDeviceSession, transaction);
            }
            return startFaceCheck(newDeviceSession, transaction);
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new VerifyEnrollmentResult.Unavailable();
        }
    }

    /**
     * This session's KEY_EXCHANGE transaction with one more attempt, counted before the answer is checked so a lost
     * race cannot grant a free try; empty when there is none or another request changed it first.
     */
    private Optional<CacheTransaction<EnrollmentTransaction>> countVerifyAttempt(AdmittedSession newDeviceSession) {
        Optional<CacheTransaction<EnrollmentTransaction>> waiting =
                enrollmentTransactions.findOpenAt(newDeviceSession, EnrollmentState.KEY_EXCHANGE);
        if (waiting.isEmpty()) {
            return Optional.empty();
        }
        EnrollmentTransaction withAttempt = waiting.get().payload().countVerifyAttempt();
        return enrollmentTransactions.update(waiting.get(), withAttempt);
    }

    /** The response opens with Ksrv and echoes this enrollment and the exact challenge; compared in constant time. */
    private boolean provesDeviceKey(EnrollmentTransaction enrollment, String challengeResponse) {
        Optional<OpenedChallenge> opened = challengeSealer.openResponse(enrollment.serverPrivateJwk(), challengeResponse);
        if (opened.isEmpty()) {
            return false;
        }
        if (!opened.get().enrollmentId().equals(enrollment.id())) {
            return false;
        }
        String answeredDigest = EnrollmentDigests.digest(opened.get().challenge());
        return EnrollmentDigests.sameDigest(enrollment.challengeDigest(), answeredDigest);
    }

    private VerifyEnrollmentResult wrongChallenge(AdmittedSession newDeviceSession,
                                                  CacheTransaction<EnrollmentTransaction> transaction) {
        EnrollmentTransaction enrollment = transaction.payload();
        if (enrollment.attemptsExhausted(enrollmentPolicy)) {
            endEnrollment(newDeviceSession, transaction);
            return new VerifyEnrollmentResult.WrongChallenge(NO_ATTEMPTS_LEFT);
        }
        int attemptsLeft = enrollmentPolicy.maxVerifyAttempts() - enrollment.verifyAttempts();
        return new VerifyEnrollmentResult.WrongChallenge(attemptsLeft);
    }

    /** Asks the MFA service for a FACE transaction bound to this enrollment; no usable factor ends the enrollment. */
    private VerifyEnrollmentResult startFaceCheck(AdmittedSession newDeviceSession,
                                                  CacheTransaction<EnrollmentTransaction> transaction) {
        CreateResult faceTransaction = mfaTransactionPort.create(FaceCheckRequests.create(transaction));
        return switch (faceTransaction) {
            case CreateResult.NoUsableFactor() -> {
                endEnrollment(newDeviceSession, transaction);
                yield new VerifyEnrollmentResult.NoUsableFactor();
            }
            case CreateResult.Created created -> recordMfaRequired(transaction, created);
        };
    }

    /** Moves the enrollment to MFA_REQUIRED; the app gets the earlier of the FACE and the enrollment deadlines. */
    private VerifyEnrollmentResult recordMfaRequired(CacheTransaction<EnrollmentTransaction> transaction,
                                                     CreateResult.Created faceTransaction) {
        EnrollmentTransaction mfaRequired = transaction.payload().markMfaRequired(faceTransaction.mfaTransactionId());
        Optional<CacheTransaction<EnrollmentTransaction>> saved = enrollmentTransactions.update(transaction, mfaRequired);
        if (saved.isEmpty()) {
            return new VerifyEnrollmentResult.Conflict();
        }
        Instant expiresAt = earlierOf(faceTransaction.expiresAt(), transaction.expiresAt());
        return new VerifyEnrollmentResult.MfaRequired(faceTransaction.mfaTransactionId(), expiresAt);
    }

    /** A failed enrollment leaves nothing behind: the transaction goes, then the restricted session. */
    private void endEnrollment(AdmittedSession newDeviceSession, CacheTransaction<EnrollmentTransaction> transaction) {
        enrollmentTransactions.remove(transaction);
        sessionService.end(new SessionLookup(newDeviceSession.channel(), newDeviceSession.sessionId()));
    }

    private static Instant earlierOf(Instant first, Instant second) {
        if (first.isBefore(second)) {
            return first;
        }
        return second;
    }
}
