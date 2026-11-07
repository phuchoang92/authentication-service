package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.AuthorizeEnrollmentCommand;
import com.vpbank.dcp.auth.application.port.in.AuthorizeEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.AuthorizationTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CheckResult;
import com.vpbank.dcp.auth.application.port.out.model.MfaCheckRequest;
import com.vpbank.dcp.auth.application.result.AuthorizeEnrollmentResult;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * The primary device that approved a request reads its FACE + OTP outcome (slice 6). PASSED hands it a one-time
 * authorization token to show as a QR; Auth keeps only the token's digest. FAILED and EXPIRED close the request.
 *
 * <p>Six collaborators: the primary check, the request store and the MFA check, plus the token, its lifetime from
 * the policy and the clock that dates it.
 */
@RequiredArgsConstructor
public final class AuthorizeEnrollmentService implements AuthorizeEnrollmentUseCase {
    @NonNull
    private final TrustedDeviceService trustedDeviceService;
    @NonNull
    private final ApprovalRequests approvalRequests;
    @NonNull
    private final MfaTransactionPort mfaTransactionPort;
    @NonNull
    private final AuthorizationTokenGenerator authorizationTokenGenerator;
    @NonNull
    private final EnrollmentPolicy enrollmentPolicy;
    @NonNull
    private final Clock clock;

    @Override
    public AuthorizeEnrollmentResult authorize(AuthorizeEnrollmentCommand command) {
        AdmittedSession primaryDeviceSession = command.admitted();
        try {
            Optional<TrustedDeviceId> primaryDeviceId = trustedDeviceService.primaryDeviceIdOf(primaryDeviceSession);
            if (primaryDeviceId.isEmpty()) {
                return new AuthorizeEnrollmentResult.NotPrimaryDevice();
            }
            Optional<DeviceEnrollment> approvedRequest = findApprovedBy(primaryDeviceId.get(), command);
            if (approvedRequest.isEmpty()) {
                return new AuthorizeEnrollmentResult.Conflict();
            }
            MfaCheckRequest faceAndOtpCheck = ApprovalCheckRequests.check(approvedRequest.get());
            CheckResult outcome = mfaTransactionPort.check(faceAndOtpCheck);
            return answerOutcome(approvedRequest.get(), faceAndOtpCheck, outcome);
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new AuthorizeEnrollmentResult.Unavailable();
        }
    }

    /** The named request, open, with its check running, and approved by this device: only the approver collects. */
    private Optional<DeviceEnrollment> findApprovedBy(TrustedDeviceId primaryDeviceId,
                                                      AuthorizeEnrollmentCommand command) {
        Optional<DeviceEnrollment> waitingRequest = approvalRequests.findOpenAt(
                command.enrollmentId(),
                command.admitted(),
                EnrollmentState.WAITING_APPROVAL);
        if (waitingRequest.isEmpty()) {
            return Optional.empty();
        }
        DeviceEnrollment request = waitingRequest.get();
        boolean approvedByThisDevice = request.hasApprovalInProgress()
                && primaryDeviceId.equals(request.actorDeviceId());
        if (!approvedByThisDevice) {
            return Optional.empty();
        }
        return waitingRequest;
    }

    /** PASSED issues the token; FAILED and EXPIRED close the request; PENDING and REJECTED leave it waiting. */
    private AuthorizeEnrollmentResult answerOutcome(DeviceEnrollment approvedRequest,
                                                    MfaCheckRequest faceAndOtpCheck,
                                                    CheckResult outcome) {
        return switch (outcome) {
            case CheckResult.Pending() -> new AuthorizeEnrollmentResult.MfaPending();
            case CheckResult.Rejected() -> new AuthorizeEnrollmentResult.Rejected();
            case CheckResult.Failed() -> {
                approvalRequests.close(approvedRequest.fail());
                yield new AuthorizeEnrollmentResult.MfaFailed();
            }
            case CheckResult.Expired() -> {
                approvalRequests.close(approvedRequest.expire());
                yield new AuthorizeEnrollmentResult.MfaExpired();
            }
            case CheckResult.Passed(_) -> issueAuthorizationToken(approvedRequest, faceAndOtpCheck);
        };
    }

    /** The token is handed out once; Auth keeps its digest, its deadline and which factors the approver passed. */
    private AuthorizeEnrollmentResult issueAuthorizationToken(DeviceEnrollment approvedRequest,
                                                              MfaCheckRequest faceAndOtpCheck) {
        String authorizationToken = authorizationTokenGenerator.next();
        String tokenDigest = EnrollmentDigests.digest(authorizationToken);
        Instant tokenLifetimeEnd = clock.instant().plus(enrollmentPolicy.approvalTokenLifetime());
        Instant tokenExpiresAt = earlierOf(tokenLifetimeEnd, approvedRequest.expiresAt());

        DeviceEnrollment authorizedRequest =
                approvedRequest.authorize(tokenDigest, tokenExpiresAt, faceAndOtpCheck.factorClaim());
        Optional<DeviceEnrollment> saved = approvalRequests.update(authorizedRequest);
        if (saved.isEmpty()) {
            return new AuthorizeEnrollmentResult.Conflict();
        }
        return new AuthorizeEnrollmentResult.Authorized(approvedRequest.id(), authorizationToken, tokenExpiresAt);
    }

    private static Instant earlierOf(Instant first, Instant second) {
        if (first.isBefore(second)) {
            return first;
        }
        return second;
    }
}
