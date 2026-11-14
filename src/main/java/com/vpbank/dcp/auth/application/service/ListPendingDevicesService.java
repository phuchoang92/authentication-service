package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.ListPendingDevicesCommand;
import com.vpbank.dcp.auth.application.port.in.ListPendingDevicesUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.result.ListPendingDevicesResult;
import com.vpbank.dcp.auth.application.result.PendingDeviceSummary;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * The primary device, on its full ACTIVE session, lists the devices waiting for its approval (slice 6): each open
 * request with the platform saved on the enrollment.
 */
@RequiredArgsConstructor
public final class ListPendingDevicesService implements ListPendingDevicesUseCase {
    @NonNull
    private final TrustedDeviceService trustedDeviceService;
    @NonNull
    private final ApprovalRequests approvalRequests;

    @Override
    public ListPendingDevicesResult pending(ListPendingDevicesCommand command) {
        AdmittedSession primaryDeviceSession = command.admitted();
        try {
            Optional<TrustedDeviceId> primaryDeviceId = trustedDeviceService.primaryDeviceIdOf(primaryDeviceSession);
            if (primaryDeviceId.isEmpty()) {
                return new ListPendingDevicesResult.NotPrimaryDevice();
            }
            List<DeviceEnrollment> openRequests = approvalRequests.listOpenFor(primaryDeviceSession);
            return new ListPendingDevicesResult.Pending(summariesOf(openRequests));
        } catch (RepositoryUnavailableException failure) {
            return new ListPendingDevicesResult.Unavailable();
        }
    }

    private static List<PendingDeviceSummary> summariesOf(List<DeviceEnrollment> openRequests) {
        List<PendingDeviceSummary> summaries = new ArrayList<>();
        for (DeviceEnrollment request : openRequests) {
            if (request.candidateKey() != null) {
                summaries.add(summaryOf(request));
            }
        }
        return summaries;
    }

    private static PendingDeviceSummary summaryOf(DeviceEnrollment request) {
        return new PendingDeviceSummary(
                request.id(),
                request.deviceId(),
                request.candidateKey().platform(),
                request.state(),
                request.expiresAt());
    }

}
