package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.ConfirmEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.ConfirmTrustCommand;
import com.vpbank.dcp.auth.application.command.IssueSessionCommand;
import com.vpbank.dcp.auth.application.port.in.ConfirmEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CheckResult;
import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.result.ConfirmEnrollmentResult;
import com.vpbank.dcp.auth.application.service.SessionService.IssuedSession;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceKey;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Step 3 of a new device trusting itself (DD 20 §4): reads the FACE outcome. PASSED trusts the device in one SQL
 * commit (the enrollment row is inserted already COMPLETED), then removes the transaction, ends the restricted
 * session and issues a full ACTIVE one; FAILED and EXPIRED remove the transaction and end the restricted session.
 * The SQL commit comes before anything in the cache changes, so a database failure leaves the enrollment as it
 * was and the app calls confirm again.
 */
@RequiredArgsConstructor
public final class ConfirmEnrollmentService implements ConfirmEnrollmentUseCase {
    @NonNull
    private final SessionService sessionService;
    @NonNull
    private final EnrollmentTransactions enrollmentTransactions;
    @NonNull
    private final TrustedDeviceService trustedDeviceService;
    @NonNull
    private final MfaTransactionPort mfaTransactionPort;

    @Override
    public ConfirmEnrollmentResult confirm(ConfirmEnrollmentCommand command) {
        AdmittedSession newDeviceSession = command.admitted();
        if (!newDeviceSession.restricted()) {
            return new ConfirmEnrollmentResult.Conflict();
        }
        try {
            Optional<CacheTransaction<EnrollmentTransaction>> waiting =
                    enrollmentTransactions.findOpenAt(newDeviceSession, EnrollmentState.MFA_REQUIRED);
            if (waiting.isEmpty()) {
                return new ConfirmEnrollmentResult.Conflict();
            }
            CheckResult faceCheck = mfaTransactionPort.check(FaceCheckRequests.check(waiting.get().payload()));
            return answerFaceCheck(command, waiting.get(), faceCheck);
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new ConfirmEnrollmentResult.Unavailable();
        }
    }

    /** PASSED commits the trust; FAILED and EXPIRED end the enrollment; PENDING and REJECTED leave it waiting. */
    private ConfirmEnrollmentResult answerFaceCheck(ConfirmEnrollmentCommand command,
                                                    CacheTransaction<EnrollmentTransaction> transaction,
                                                    CheckResult faceCheck) {
        AdmittedSession newDeviceSession = command.admitted();
        return switch (faceCheck) {
            case CheckResult.Pending() -> new ConfirmEnrollmentResult.MfaPending();
            case CheckResult.Rejected() -> new ConfirmEnrollmentResult.Rejected();
            case CheckResult.Failed() -> {
                endEnrollment(newDeviceSession, transaction);
                yield new ConfirmEnrollmentResult.MfaFailed();
            }
            case CheckResult.Expired() -> {
                endEnrollment(newDeviceSession, transaction);
                yield new ConfirmEnrollmentResult.MfaExpired();
            }
            case CheckResult.Passed(String receiptDigest) -> commitTrust(command, transaction, receiptDigest);
        };
    }

    /**
     * The database commit comes first. A failure there changes nothing, and confirm can be called again. The commit
     * is also what lets only one confirm through: a second one finds the enrollment row and commits nothing. A
     * restricted session already gone (a logout) commits nothing. The session ending between this check and its
     * consumption leaves the device trusted without an ACTIVE session: the next login is ACTIVE.
     */
    private ConfirmEnrollmentResult commitTrust(ConfirmEnrollmentCommand command,
                                                CacheTransaction<EnrollmentTransaction> transaction,
                                                String receiptDigest) {
        AdmittedSession newDeviceSession = command.admitted();
        SessionLookup restrictedSession = restrictedSessionOf(newDeviceSession);
        if (sessionService.isLive(restrictedSession)) {
            enrollmentTransactions.remove(transaction);
            return new ConfirmEnrollmentResult.Conflict();
        }
        Optional<TrustedDevice> trustedDevice = trustDevice(newDeviceSession, transaction, receiptDigest);
        if (trustedDevice.isEmpty()) {
            return new ConfirmEnrollmentResult.Conflict();
        }

        enrollmentTransactions.remove(transaction);
        boolean sessionConsumed = sessionService.consume(restrictedSession);
        if (!sessionConsumed) {
            return new ConfirmEnrollmentResult.Conflict();
        }
        return issueActiveSession(trustedDevice.get(), command);
    }

    /**
     * Inserts the enrollment row already COMPLETED and makes the device trusted, in one database commit; empty when
     * this enrollment was committed already.
     */
    private Optional<TrustedDevice> trustDevice(AdmittedSession newDeviceSession,
                                                CacheTransaction<EnrollmentTransaction> transaction,
                                                String receiptDigest) {
        EnrollmentTransaction enrollment = transaction.payload();
        ConfirmTrustCommand trust = ConfirmTrustCommand.builder()
                .enrollment(DeviceEnrollment.fromTransaction(enrollment, transaction.expiresAt()))
                .restrictedSessionId(newDeviceSession.sessionId())
                .deviceKey(new DeviceKey(enrollment.devicePublicJwk(), enrollment.platform()))
                .receiptDigest(receiptDigest)
                .correlationId(newDeviceSession.sessionId().toString())
                .build();
        return trustedDeviceService.confirmTrust(trust);
    }

    /** The full ACTIVE session of the newly trusted device, sealed to the key the app sent with this request. */
    private ConfirmEnrollmentResult issueActiveSession(TrustedDevice trustedDevice, ConfirmEnrollmentCommand command) {
        IssueSessionCommand newSession = IssueSessionCommand.builder()
                .sessionId(sessionService.newSessionId())
                .customerId(trustedDevice.customerId())
                .channel(command.admitted().channel())
                .deviceId(trustedDevice.deviceId())
                .tokenEncryptionKey(command.tokenEncryptionKey())
                .build();
        IssuedSession activeSession = sessionService.issueActive(newSession);
        return new ConfirmEnrollmentResult.Trusted(
                activeSession.tokenEnvelope(),
                activeSession.session().idleExpiresAt(),
                activeSession.session().absoluteExpiresAt());
    }

    /** A failed or expired enrollment leaves nothing behind: the transaction goes, then the restricted session. */
    private void endEnrollment(AdmittedSession newDeviceSession, CacheTransaction<EnrollmentTransaction> transaction) {
        enrollmentTransactions.remove(transaction);
        sessionService.end(restrictedSessionOf(newDeviceSession));
    }

    private static SessionLookup restrictedSessionOf(AdmittedSession newDeviceSession) {
        return new SessionLookup(newDeviceSession.channel(), newDeviceSession.sessionId());
    }
}
