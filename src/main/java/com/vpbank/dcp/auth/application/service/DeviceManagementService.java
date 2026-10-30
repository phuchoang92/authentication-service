package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.ListDevicesCommand;
import com.vpbank.dcp.auth.application.port.in.ListDevicesUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.StoredSession;
import com.vpbank.dcp.auth.application.result.DeviceSummary;
import com.vpbank.dcp.auth.application.result.ListDevicesResult;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.Session;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Device management use cases (slice 8 seed; revoke, rename and history follow): resolve the caller's
 * session once, decide what that session may do, then compose {@link TrustedDeviceService} actions.
 */
@RequiredArgsConstructor
public final class DeviceManagementService implements ListDevicesUseCase {
    @NonNull private final SessionService sessionService;
    @NonNull private final TrustedDeviceService trustedDeviceService;

    @Override
    public ListDevicesResult list(ListDevicesCommand command) {
        try {
            Optional<StoredSession> liveSession = sessionService.findLive(command.token());
            if (liveSession.isEmpty()) {
                return new ListDevicesResult.SessionGone();
            }
            Session session = liveSession.get().session();

            // A restricted session may only log out or run the trust flows (DD 20 §3).
            if (session.status() != SessionStatus.ACTIVE) {
                return new ListDevicesResult.DeviceTrustRequired();
            }

            List<DeviceSummary> devices = trustedDeviceService.listDevices(session.customerId(), session.channel());
            return new ListDevicesResult.Devices(devices);
        } catch (RepositoryUnavailableException failure) {
            return new ListDevicesResult.Unavailable();
        }
    }
}
