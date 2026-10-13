package com.vpbank.dcp.core.port.out.device;

import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import java.util.Optional;
import java.util.UUID;

/** Two reads: pre-password public key, then current owner-bound device facts. */
public interface LoginDeviceRepository {
    Optional<StoredDeviceKey> keyForProof(String publicBindingId);

    Optional<LoginDeviceSnapshot> current(UUID customerId, String channel,
                                          String installationId, String publicBindingId);

    Optional<LoginDeviceSnapshot> currentByBinding(UUID customerId, String channel,
                                                   String installationId, UUID bindingId);
}
