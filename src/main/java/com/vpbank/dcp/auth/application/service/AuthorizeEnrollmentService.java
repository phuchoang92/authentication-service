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
 * Asking again once the token is out (the device lost the answer, or sent the request twice) replaces the token
 * with a new one: the first cannot be handed out a second time, because only its digest was kept.
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
            Optional<DeviceEnrollment> found = findApprovedBy(primaryDeviceId.get(), command);
            if (found.isEmpty()) {
                return new AuthorizeEnrollmentResult.Conflict();
            }
            DeviceEnrollment approvedRequest = found.get();
            if (approvedRequest.isAuthorized()) {
                return reissueAuthorizationToken(approvedRequest);
            }
            MfaCheckRequest faceAndOtpCheck = ApprovalCheckRequests.check(approvedRequest);
            CheckResult outcome = mfaTransactionPort.check(faceAndOtpCheck);
            return answerOutcome(approvedRequest, faceAndOtpCheck, outcome);
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new AuthorizeEnrollmentResult.Unavailable();
        }
    }

    /**
     * The named request, open and approved by this device: its check is running, or it passed and the token is
     * out. Only the approver collects.
     */
    private Optional<DeviceEnrollment> findApprovedBy(TrustedDeviceId primaryDeviceId,
                                                      AuthorizeEnrollmentCommand command) {
        Optional<DeviceEnrollment> openRequest = approvalRequests.findOpen(command.enrollmentId(), command.admitted());
        if (openRequest.isEmpty()) {
            return Optional.empty();
        }
        // A request nobody approved yet has no approving device, so it is not this device's either.
        boolean approvedByThisDevice = openRequest.get().wasApprovedBy(primaryDeviceId);
        if (!approvedByThisDevice) {
            return Optional.empty();
        }
        return openRequest;
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

    /** The first token: Auth keeps its digest, its deadline and which factors the approver passed. */
    private AuthorizeEnrollmentResult issueAuthorizationToken(DeviceEnrollment approvedRequest,
                                                              MfaCheckRequest faceAndOtpCheck) {
        String authorizationToken = authorizationTokenGenerator.next();
        String tokenDigest = EnrollmentDigests.digest(authorizationToken);
        Instant tokenLifetimeEnd = clock.instant().plus(enrollmentPolicy.approvalTokenLifetime());
        Instant tokenExpiresAt = earlierOf(tokenLifetimeEnd, approvedRequest.expiresAt());

        DeviceEnrollment authorizedRequest =
                approvedRequest.authorize(tokenDigest, tokenExpiresAt, faceAndOtpCheck.factorClaim());
        return handOut(authorizedRequest, authorizationToken);
    }

    /**
     * The token is already out and the approver asks again: a new token takes its place and the earlier one
     * stops working. The deadline and the claim attempts stay as they are, the MFA service is not asked again.
     * Once the token's deadline has passed there is nothing to hand out.
     */
    private AuthorizeEnrollmentResult reissueAuthorizationToken(DeviceEnrollment authorizedRequest) {
        Instant now = clock.instant();
        if (authorizedRequest.authorizationExpired(now)) {
            return new AuthorizeEnrollmentResult.Conflict();
        }
        String authorizationToken = authorizationTokenGenerator.next();
        String tokenDigest = EnrollmentDigests.digest(authorizationToken);

        DeviceEnrollment reissuedRequest = authorizedRequest.reissueAuthorization(tokenDigest, now);
        return handOut(reissuedRequest, authorizationToken);
    }

    /** Stores the request with its token digest, then answers with the token; a racing change wins. */
    private AuthorizeEnrollmentResult handOut(DeviceEnrollment requestWithToken, String authorizationToken) {
        Optional<DeviceEnrollment> saved = approvalRequests.update(requestWithToken);
        if (saved.isEmpty()) {
            return new AuthorizeEnrollmentResult.Conflict();
        }
        return new AuthorizeEnrollmentResult.Authorized(
                requestWithToken.id(),
                authorizationToken,
                requestWithToken.authorizationExpiresAt());
    }

    private static Instant earlierOf(Instant first, Instant second) {
        if (first.isBefore(second)) {
            return first;
        }
        return second;
    }
}
