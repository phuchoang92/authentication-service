package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.ClaimEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.IssueSessionCommand;
import com.vpbank.dcp.auth.application.port.in.ClaimEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.application.result.ClaimEnrollmentResult;
import com.vpbank.dcp.auth.application.service.SessionService.IssuedSession;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import java.time.Clock;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * The new device claims the one-time token the primary device showed as a QR (slice 6), from any of its restricted
 * sessions. The right token makes the device trusted and primary in one SQL commit, ends the restricted session and
 * issues a full ACTIVE one; the last wrong token, or a token past its deadline, closes the request and ends the
 * restricted session. The SQL commit comes before the session is ended, so a database failure leaves the request
 * waiting for its token and the app claims again.
 */
@RequiredArgsConstructor
public final class ClaimEnrollmentService implements ClaimEnrollmentUseCase {
    /** The last wrong token leaves no attempt; the request is already failed when it is reported. */
    private static final int NO_ATTEMPTS_LEFT = 0;

    @NonNull
    private final SessionService sessionService;
    @NonNull
    private final ApprovalRequests approvalRequests;
    @NonNull
    private final TrustedDeviceService trustedDeviceService;
    @NonNull
    private final EnrollmentPolicy enrollmentPolicy;
    @NonNull
    private final Clock clock;

    @Override
    public ClaimEnrollmentResult claim(ClaimEnrollmentCommand command) {
        AdmittedSession newDeviceSession = command.admitted();
        if (!newDeviceSession.restricted()) {
            return new ClaimEnrollmentResult.Conflict();
        }
        try {
            Optional<DeviceEnrollment> authorizedRequest = findWaitingForToken(newDeviceSession);
            if (authorizedRequest.isEmpty()) {
                return new ClaimEnrollmentResult.Conflict();
            }
            return checkToken(command, authorizedRequest.get());
        } catch (RepositoryUnavailableException failure) {
            return new ClaimEnrollmentResult.Unavailable();
        }
    }

    /**
     * The device's latest request, when the primary device authorized it and it is still open. The claim is bound
     * to the device that made the request, from any of its restricted sessions.
     */
    private Optional<DeviceEnrollment> findWaitingForToken(AdmittedSession newDeviceSession) {
        Optional<DeviceEnrollment> latestRequest = approvalRequests.latestOf(newDeviceSession);
        if (latestRequest.isEmpty()) {
            return Optional.empty();
        }
        DeviceEnrollment request = latestRequest.get();
        boolean waitingForToken = request.state() == EnrollmentState.WAITING_AUTHORIZATION
                && request.isOpen(clock.instant());
        if (!waitingForToken) {
            return Optional.empty();
        }
        return latestRequest;
    }

    /** A token past its deadline closes the request; otherwise the attempt is counted, then the token compared. */
    private ClaimEnrollmentResult checkToken(ClaimEnrollmentCommand command, DeviceEnrollment authorizedRequest) {
        AdmittedSession newDeviceSession = command.admitted();
        if (authorizedRequest.authorizationExpired(clock.instant())) {
            endClaim(newDeviceSession, authorizedRequest.expire());
            return new ClaimEnrollmentResult.AuthorizationExpired();
        }

        // The attempt is counted before the token is compared, so a lost race cannot grant a free try.
        DeviceEnrollment withAttempt = authorizedRequest.countClaimAttempt();
        Optional<DeviceEnrollment> counted = approvalRequests.update(withAttempt);
        if (counted.isEmpty()) {
            return new ClaimEnrollmentResult.Conflict();
        }
        DeviceEnrollment countedRequest = counted.get();
        if (!presentsTheToken(countedRequest, command.authorizationToken())) {
            return wrongToken(newDeviceSession, countedRequest);
        }
        return commitTrust(command, countedRequest);
    }

    /** Digest to digest, in constant time. */
    private static boolean presentsTheToken(DeviceEnrollment countedRequest, String authorizationToken) {
        String presentedDigest = EnrollmentDigests.digest(authorizationToken);
        return EnrollmentDigests.sameDigest(countedRequest.authorizationTokenDigest(), presentedDigest);
    }

    private ClaimEnrollmentResult wrongToken(AdmittedSession newDeviceSession, DeviceEnrollment countedRequest) {
        if (countedRequest.claimAttemptsExhausted(enrollmentPolicy)) {
            endClaim(newDeviceSession, countedRequest.fail());
            return new ClaimEnrollmentResult.WrongAuthorization(NO_ATTEMPTS_LEFT);
        }
        int attemptsLeft = enrollmentPolicy.maxClaimAttempts() - countedRequest.authorizationAttempts();
        return new ClaimEnrollmentResult.WrongAuthorization(attemptsLeft);
    }

    /**
     * The database commit comes first. A failure there changes nothing but the attempt already counted, and the
     * app claims again. The commit is also what lets only one claim through: it goes on only while the request is
     * at the version this claim counted. A restricted session already gone (a logout) commits nothing. The session
     * ending between this check and its consumption leaves the device trusted without an ACTIVE session: the next
     * login is ACTIVE.
     */
    private ClaimEnrollmentResult commitTrust(ClaimEnrollmentCommand command, DeviceEnrollment countedRequest) {
        AdmittedSession newDeviceSession = command.admitted();
        SessionLookup restrictedSession = restrictedSessionOf(newDeviceSession);
        if (!sessionService.isLive(restrictedSession)) {
            return new ClaimEnrollmentResult.Conflict();
        }
        DeviceEnrollment consumedRequest = countedRequest.consumeAuthorization(clock.instant());
        String correlationId = newDeviceSession.sessionId().toString();
        Optional<TrustedDevice> trustedDevice =
                trustedDeviceService.confirmTrustByApproval(consumedRequest, correlationId);
        if (trustedDevice.isEmpty()) {
            return new ClaimEnrollmentResult.Conflict();
        }

        boolean sessionConsumed = sessionService.consume(restrictedSession);
        if (!sessionConsumed) {
            return new ClaimEnrollmentResult.Conflict();
        }
        return issueActiveSession(trustedDevice.get(), command);
    }

    /** The full ACTIVE session of the newly trusted device, sealed to the key the app sent with this request. */
    private ClaimEnrollmentResult issueActiveSession(TrustedDevice trustedDevice, ClaimEnrollmentCommand command) {
        IssueSessionCommand newSession = IssueSessionCommand.builder()
                .sessionId(sessionService.newSessionId())
                .customerId(trustedDevice.customerId())
                .channel(command.admitted().channel())
                .deviceId(trustedDevice.deviceId())
                .tokenEncryptionKey(command.tokenEncryptionKey())
                .build();
        IssuedSession activeSession = sessionService.issueActive(newSession);
        return new ClaimEnrollmentResult.Trusted(
                activeSession.tokenEnvelope(),
                activeSession.session().idleExpiresAt(),
                activeSession.session().absoluteExpiresAt());
    }

    /** A closed request is written first, then the restricted session is dropped. */
    private void endClaim(AdmittedSession newDeviceSession, DeviceEnrollment closedRequest) {
        approvalRequests.close(closedRequest);
        sessionService.end(restrictedSessionOf(newDeviceSession));
    }

    private static SessionLookup restrictedSessionOf(AdmittedSession newDeviceSession) {
        return new SessionLookup(newDeviceSession.channel(), newDeviceSession.sessionId());
    }
}
