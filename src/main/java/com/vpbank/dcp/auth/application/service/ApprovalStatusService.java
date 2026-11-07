package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.ApprovalStatusCommand;
import com.vpbank.dcp.auth.application.port.in.ApprovalStatusUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.result.ApprovalStatusResult;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import java.time.Clock;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * The new device, from any of its restricted sessions, polls its latest approval request (slice 6, slice 11):
 * waiting, authorized, or how it ended. Nothing is written.
 */
@RequiredArgsConstructor
public final class ApprovalStatusService implements ApprovalStatusUseCase {
    @NonNull
    private final ApprovalRequests approvalRequests;
    @NonNull
    private final Clock clock;

    @Override
    public ApprovalStatusResult status(ApprovalStatusCommand command) {
        AdmittedSession newDeviceSession = command.admitted();
        if (!newDeviceSession.restricted()) {
            return new ApprovalStatusResult.NoRequest();
        }
        try {
            Optional<DeviceEnrollment> latestRequest = approvalRequests.latestOf(newDeviceSession);
            if (latestRequest.isEmpty()) {
                return new ApprovalStatusResult.NoRequest();
            }
            return statusOf(latestRequest.get());
        } catch (RepositoryUnavailableException failure) {
            return new ApprovalStatusResult.Unavailable();
        }
    }

    /** An open request past its window is reported as expired without touching the row. */
    private ApprovalStatusResult statusOf(DeviceEnrollment request) {
        EnrollmentState state = request.state();
        if (state.open() && !request.isOpen(clock.instant())) {
            state = EnrollmentState.EXPIRED;
        }
        return new ApprovalStatusResult.Status(request.id(), state, request.expiresAt());
    }
}
