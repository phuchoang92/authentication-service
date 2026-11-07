package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.ListPendingDevicesCommand;
import com.vpbank.dcp.auth.application.port.in.ListPendingDevicesUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.application.result.ListPendingDevicesResult;
import com.vpbank.dcp.auth.application.result.PendingDeviceSummary;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * The primary device, on its full ACTIVE session, lists the devices waiting for its approval (slice 6): each open
 * request with the platform of the device row it targets. Nothing is written.
 */
@RequiredArgsConstructor
public final class ListPendingDevicesService implements ListPendingDevicesUseCase {
    @NonNull
    private final TrustedDeviceService trustedDeviceService;
    @NonNull
    private final ApprovalRequests approvalRequests;
    @NonNull
    private final TrustedDeviceRepository trustedDeviceRepository;

    @Override
    public ListPendingDevicesResult pending(ListPendingDevicesCommand command) {
        AdmittedSession primaryDeviceSession = command.admitted();
        try {
            Optional<TrustedDeviceId> primaryDeviceId = trustedDeviceService.primaryDeviceIdOf(primaryDeviceSession);
            if (primaryDeviceId.isEmpty()) {
                return new ListPendingDevicesResult.NotPrimaryDevice();
            }
            List<DeviceEnrollment> openRequests = approvalRequests.listOpenFor(primaryDeviceSession);
            List<TrustedDevice> liveDevices = trustedDeviceRepository.findLive(
                    primaryDeviceSession.customerId(),
                    primaryDeviceSession.channel());
            return new ListPendingDevicesResult.Pending(summariesOf(openRequests, liveDevices));
        } catch (RepositoryUnavailableException failure) {
            return new ListPendingDevicesResult.Unavailable();
        }
    }

    /** A request whose target device row is no longer live is left out. */
    private static List<PendingDeviceSummary> summariesOf(List<DeviceEnrollment> openRequests,
                                                          List<TrustedDevice> liveDevices) {
        List<PendingDeviceSummary> summaries = new ArrayList<>();
        for (DeviceEnrollment request : openRequests) {
            Optional<TrustedDevice> targetDevice = findById(liveDevices, request.targetDeviceId());
            if (targetDevice.isPresent()) {
                summaries.add(summaryOf(request, targetDevice.get()));
            }
        }
        return summaries;
    }

    private static PendingDeviceSummary summaryOf(DeviceEnrollment request, TrustedDevice targetDevice) {
        return new PendingDeviceSummary(
                request.id(),
                request.deviceId(),
                targetDevice.platform(),
                request.state(),
                request.expiresAt());
    }

    private static Optional<TrustedDevice> findById(List<TrustedDevice> devices, TrustedDeviceId deviceId) {
        return devices.stream()
                .filter(device -> device.id().equals(deviceId))
                .findFirst();
    }
}
