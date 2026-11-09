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
 * customer, and the request records which device approved it. No usable factor fails the request. The device that
 * approved may call again (it lost the answer, or sent the request twice) and gets the same check again.
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
            Optional<DeviceEnrollment> found = findApprovableBy(primaryDeviceId.get(), command);
            if (found.isEmpty()) {
                return new ApproveEnrollmentResult.Conflict();
            }
            DeviceEnrollment request = found.get();
            // The create is the same for the first approve and for a repeat: the MFA service opens the check
            // once and answers a repeat with the check it already opened (DD 20 §5.2).
            CreateResult faceAndOtp = mfaTransactionPort.create(ApprovalCheckRequests.create(request));
            return answerApproval(primaryDeviceId.get(), request, faceAndOtp);
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new ApproveEnrollmentResult.Unavailable();
        }
    }

    /** The named request, open and waiting for approval: not approved yet, or approved by this same device. */
    private Optional<DeviceEnrollment> findApprovableBy(TrustedDeviceId primaryDeviceId,
                                                        ApproveEnrollmentCommand command) {
        Optional<DeviceEnrollment> waitingRequest = approvalRequests.findOpenAt(
                command.enrollmentId(),
                command.admitted(),
                EnrollmentState.WAITING_APPROVAL);
        if (waitingRequest.isEmpty()) {
            return Optional.empty();
        }
        DeviceEnrollment request = waitingRequest.get();
        boolean approvedByAnotherDevice = request.hasApprovalInProgress()
                && !request.wasApprovedBy(primaryDeviceId);
        if (approvedByAnotherDevice) {
            return Optional.empty();
        }
        return waitingRequest;
    }

    private ApproveEnrollmentResult answerApproval(TrustedDeviceId primaryDeviceId,
                                                   DeviceEnrollment request,
                                                   CreateResult faceAndOtp) {
        return switch (faceAndOtp) {
            case CreateResult.NoUsableFactor() -> {
                approvalRequests.close(request.fail());
                yield new ApproveEnrollmentResult.NoUsableFactor();
            }
            case CreateResult.Created created -> {
                if (request.hasApprovalInProgress()) {
                    yield answerAgain(request, created);
                }
                yield recordApproval(primaryDeviceId, request, created);
            }
        };
    }

    /** Marks the request approved by this device and answers with the check to complete. */
    private ApproveEnrollmentResult recordApproval(TrustedDeviceId primaryDeviceId,
                                                   DeviceEnrollment waitingRequest,
                                                   CreateResult.Created faceAndOtp) {
        DeviceEnrollment approvedRequest = waitingRequest.approveBy(primaryDeviceId, faceAndOtp.mfaTransactionId());
        Optional<DeviceEnrollment> saved = approvalRequests.update(approvedRequest);
        if (saved.isEmpty()) {
            return new ApproveEnrollmentResult.Conflict();
        }
        return mfaRequired(waitingRequest, faceAndOtp);
    }

    /**
     * This device already approved the request: it gets the same check again and nothing is written. Should the
     * MFA service answer with another check than the one the request holds, the repeat is refused and the
     * request keeps the first.
     */
    private static ApproveEnrollmentResult answerAgain(DeviceEnrollment approvedRequest,
                                                       CreateResult.Created faceAndOtp) {
        boolean sameCheck = faceAndOtp.mfaTransactionId().equals(approvedRequest.mfaTransactionId());
        if (!sameCheck) {
            return new ApproveEnrollmentResult.Conflict();
        }
        return mfaRequired(approvedRequest, faceAndOtp);
    }

    /** The app gets the earlier of the check and the request deadlines. */
    private static ApproveEnrollmentResult mfaRequired(DeviceEnrollment request, CreateResult.Created faceAndOtp) {
        Instant expiresAt = earlierOf(faceAndOtp.expiresAt(), request.expiresAt());
        return new ApproveEnrollmentResult.MfaRequired(faceAndOtp.mfaTransactionId(), expiresAt);
    }

    private static Instant earlierOf(Instant first, Instant second) {
        if (first.isBefore(second)) {
            return first;
        }
        return second;
    }
}
