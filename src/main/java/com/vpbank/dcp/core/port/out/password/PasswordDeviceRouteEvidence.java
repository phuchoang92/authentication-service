package com.vpbank.dcp.core.port.out.password;

import com.vpbank.dcp.core.domain.device.DeviceCandidate;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Current database facts for one already verified password operation. */
public record PasswordDeviceRouteEvidence(UUID claimedBindingId,
                                          UUID lastSuccessfulBindingId,
                                          String installationHash,
                                          Optional<DeviceCandidate> candidate) {

    public PasswordDeviceRouteEvidence {
        Objects.requireNonNull(installationHash, "installationHash");
        Objects.requireNonNull(candidate, "candidate");
    }
}
