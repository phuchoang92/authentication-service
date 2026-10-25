package com.vpbank.dcp.core.password;

import com.vpbank.dcp.core.customer.SubjectId;
import com.vpbank.dcp.core.device.DeviceOwnership;
import com.vpbank.dcp.core.device.DeviceTrustDecision;
import com.vpbank.dcp.core.device.DeviceTrustPolicy;
import com.vpbank.dcp.core.device.LoginDeviceRepository;
import com.vpbank.dcp.core.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.device.LoginDeviceUnavailableException;
import java.util.Objects;
import java.util.UUID;

/** Resolves the current customer-owned device; a supplied invalid ID never becomes NEW_DEVICE. */
public final class LoginDevices {
    private final LoginDeviceRepository devices;
    private final DeviceTrustPolicy policy;

    public LoginDevices(LoginDeviceRepository devices, DeviceTrustPolicy policy) {
        this.devices = Objects.requireNonNull(devices);
        this.policy = Objects.requireNonNull(policy);
    }

    public DeviceTrustResult decide(SubjectId owner, PasswordLoginCommand command,
                                           VerifiedPasswordProofs proofs) {
        String claimedId = command.operation().claimedBindingId();
        if (claimedId == null) {
            return new DeviceTrustResult.NewDevice();
        }
        LoginDeviceSnapshot stored;
        try {
            stored = devices.current(owner, command.operation().appId(),
                    command.operation().deviceId(), claimedId).orElse(null);
        } catch (LoginDeviceUnavailableException failure) {
            return new DeviceTrustResult.Denied(LoginDenial.UNAVAILABLE);
        }
        if (stored == null || proofs.deviceKeyThumbprint() == null) {
            return new DeviceTrustResult.Denied(LoginDenial.REJECTED);
        }
        DeviceTrustDecision decision = policy.decide(
                new DeviceOwnership(owner, command.operation().appId()),
                command.operation().platform(), stored, proofs.deviceKeyThumbprint(), command.now());
        return switch (decision) {
            case LAST_TRUSTED -> new DeviceTrustResult.LastTrusted(stored);
            case OTHER_TRUSTED -> new DeviceTrustResult.OtherTrusted(stored);
            case TRUST_LAPSED -> new DeviceTrustResult.Lapsed(stored);
            case REJECTED, NEW_DEVICE -> new DeviceTrustResult.Denied(LoginDenial.REJECTED);
        };
    }
}
