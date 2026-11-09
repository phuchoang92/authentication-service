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
 * one, or no usable factor, removes the transaction and ends the restricted session. Once the key is proven, a
 * repeated verify gets the first answer again.
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
            Optional<CacheTransaction<EnrollmentTransaction>> started =
                    enrollmentTransactions.findStartedBy(newDeviceSession);
            if (started.isEmpty()) {
                return new VerifyEnrollmentResult.Conflict();
            }
            CacheTransaction<EnrollmentTransaction> transaction = started.get();
            if (transaction.payload().keyProven()) {
                return faceCheckAnswer(transaction.payload());
            }
            return checkKeyProof(command, transaction);
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new VerifyEnrollmentResult.Unavailable();
        }
    }

    /** Counts the attempt, checks the device's answer, and on the right answer starts the FACE check. */
    private VerifyEnrollmentResult checkKeyProof(VerifyEnrollmentCommand command,
                                                 CacheTransaction<EnrollmentTransaction> waiting) {
        AdmittedSession newDeviceSession = command.admitted();
        Optional<CacheTransaction<EnrollmentTransaction>> counted = countVerifyAttempt(waiting);
        if (counted.isEmpty()) {
            return new VerifyEnrollmentResult.Conflict();
        }
        CacheTransaction<EnrollmentTransaction> transaction = counted.get();
        if (!provesDeviceKey(transaction.payload(), command.challengeResponse())) {
            return wrongChallenge(newDeviceSession, transaction);
        }
        return startFaceCheck(newDeviceSession, transaction);
    }

    /**
     * One more attempt on the transaction, counted before the answer is checked so a lost race cannot grant a free
     * try; empty when another request changed the transaction first.
     */
    private Optional<CacheTransaction<EnrollmentTransaction>> countVerifyAttempt(
            CacheTransaction<EnrollmentTransaction> waiting) {
        EnrollmentTransaction withAttempt = waiting.payload().countVerifyAttempt();
        return enrollmentTransactions.update(waiting, withAttempt);
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
        Instant faceCheckDeadline = earlierOf(faceTransaction.expiresAt(), transaction.expiresAt());
        EnrollmentTransaction mfaRequired =
                transaction.payload().markMfaRequired(faceTransaction.mfaTransactionId(), faceCheckDeadline);
        Optional<CacheTransaction<EnrollmentTransaction>> saved = enrollmentTransactions.update(transaction, mfaRequired);
        if (saved.isEmpty()) {
            return new VerifyEnrollmentResult.Conflict();
        }
        return faceCheckAnswer(mfaRequired);
    }

    /**
     * The FACE transaction and its deadline, read from the enrollment, so the verify that proved the key and its
     * repeats answer the same. A repeat (the app lost the first answer, or sent the request twice) is not checked
     * again and costs no attempt: this session has already proven the key.
     */
    private static VerifyEnrollmentResult faceCheckAnswer(EnrollmentTransaction mfaRequired) {
        return new VerifyEnrollmentResult.MfaRequired(mfaRequired.mfaTransactionId(), mfaRequired.mfaExpiresAt());
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
