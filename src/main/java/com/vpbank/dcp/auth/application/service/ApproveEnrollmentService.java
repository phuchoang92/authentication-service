package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.ApproveEnrollmentCommand;
import com.vpbank.dcp.auth.application.port.in.ApproveEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CreateResult;
import com.vpbank.dcp.auth.application.result.ApproveEnrollmentResult;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Instant;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * The primary device approves one waiting request (slice 6): the MFA service opens a FACE + OTP check for the
 * customer, and the request records which device approved it. No usable factor fails the request.
 */
@RequiredArgsConstructor
public final class ApproveEnrollmentService implements ApproveEnrollmentUseCase {
    @NonNull
    private final TrustedDeviceService trustedDeviceService;
    @NonNull
    private final ApprovalRequests approvalRequests;
    @NonNull
    private final MfaTransactionPort mfaTransactionPort;

    @Override
    public ApproveEnrollmentResult approve(ApproveEnrollmentCommand command) {
        AdmittedSession primaryDeviceSession = command.admitted();
        try {
            Optional<TrustedDeviceId> primaryDeviceId = trustedDeviceService.primaryDeviceIdOf(primaryDeviceSession);
            if (primaryDeviceId.isEmpty()) {
                return new ApproveEnrollmentResult.NotPrimaryDevice();
            }
            Optional<DeviceEnrollment> waitingRequest = findAwaitingApproval(command);
            if (waitingRequest.isEmpty()) {
                return new ApproveEnrollmentResult.Conflict();
            }
            CreateResult faceAndOtp = mfaTransactionPort.create(ApprovalCheckRequests.create(waitingRequest.get()));
            return answerApproval(primaryDeviceId.get(), waitingRequest.get(), faceAndOtp);
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new ApproveEnrollmentResult.Unavailable();
        }
    }

    /** The named request, open, waiting for approval, and not already approved by a device. */
    private Optional<DeviceEnrollment> findAwaitingApproval(ApproveEnrollmentCommand command) {
        Optional<DeviceEnrollment> waitingRequest = approvalRequests.findOpenAt(
                command.enrollmentId(),
                command.admitted(),
                EnrollmentState.WAITING_APPROVAL);
        if (waitingRequest.isEmpty()) {
            return Optional.empty();
        }
        boolean alreadyApproved = waitingRequest.get().hasApprovalInProgress();
        if (alreadyApproved) {
            return Optional.empty();
        }
        return waitingRequest;
    }

    private ApproveEnrollmentResult answerApproval(TrustedDeviceId primaryDeviceId,
                                                   DeviceEnrollment waitingRequest,
                                                   CreateResult faceAndOtp) {
        return switch (faceAndOtp) {
            case CreateResult.NoUsableFactor() -> {
                approvalRequests.close(waitingRequest.fail());
                yield new ApproveEnrollmentResult.NoUsableFactor();
            }
            case CreateResult.Created created -> recordApproval(primaryDeviceId, waitingRequest, created);
        };
    }

    /** Marks the request approved by this device; the app gets the earlier of the check and the request deadlines. */
    private ApproveEnrollmentResult recordApproval(TrustedDeviceId primaryDeviceId,
                                                   DeviceEnrollment waitingRequest,
                                                   CreateResult.Created faceAndOtp) {
        DeviceEnrollment approvedRequest = waitingRequest.approveBy(primaryDeviceId, faceAndOtp.mfaTransactionId());
        Optional<DeviceEnrollment> saved = approvalRequests.update(approvedRequest);
        if (saved.isEmpty()) {
            return new ApproveEnrollmentResult.Conflict();
        }
        Instant expiresAt = earlierOf(faceAndOtp.expiresAt(), waitingRequest.expiresAt());
        return new ApproveEnrollmentResult.MfaRequired(faceAndOtp.mfaTransactionId(), expiresAt);
    }

    private static Instant earlierOf(Instant first, Instant second) {
        if (first.isBefore(second)) {
            return first;
        }
        return second;
    }
}
