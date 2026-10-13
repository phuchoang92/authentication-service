package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.device.DeviceCandidate;
import com.vpbank.dcp.core.domain.device.TrustedDeviceRoute;
import com.vpbank.dcp.core.domain.device.TrustedDeviceRouting;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.device.LoginDeviceRepository;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.device.LoginDeviceUnavailableException;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import java.util.Objects;
import java.util.UUID;

/** Resolves the current customer-owned device; a supplied invalid ID never becomes NEW_DEVICE. */
public final class ResolvePasswordDeviceService {
    private final LoginDeviceRepository devices;
    private final TrustedDeviceRouting routing;

    public ResolvePasswordDeviceService(LoginDeviceRepository devices, TrustedDeviceRouting routing) {
        this.devices = Objects.requireNonNull(devices);
        this.routing = Objects.requireNonNull(routing);
    }

    public PasswordDeviceRouteResult resolve(UUID customerId, PasswordLoginCommand command,
                                             VerifiedPasswordProofs proofs) {
        String claimedId = command.operation().claimedBindingId();
        if (claimedId == null) {
            return new PasswordDeviceRouteResult.NewDevice();
        }
        LoginDeviceSnapshot stored;
        try {
            stored = devices.current(customerId, command.operation().appId(),
                    command.operation().installationId(), claimedId).orElse(null);
        } catch (LoginDeviceUnavailableException failure) {
            return new PasswordDeviceRouteResult.Unavailable();
        }
        if (stored == null || proofs.deviceKeyThumbprint() == null) {
            return new PasswordDeviceRouteResult.Rejected();
        }
        DeviceCandidate candidate = new DeviceCandidate(stored.bindingId(), stored.customerId(),
                stored.channel(), stored.platform(), stored.installationMatches(),
                stored.active(), stored.primary(), stored.expiresAt(),
                stored.deviceKeyThumbprint().equals(proofs.deviceKeyThumbprint()));
        TrustedDeviceRoute route = routing.decide(customerId, command.operation().appId(),
                command.operation().platform(), candidate, command.now());
        return switch (route) {
            case LAST_TRUSTED -> new PasswordDeviceRouteResult.LastTrusted(stored);
            case OTHER_TRUSTED -> new PasswordDeviceRouteResult.OtherTrusted(stored);
            case REJECTED, NEW_DEVICE -> new PasswordDeviceRouteResult.Rejected();
        };
    }
}
