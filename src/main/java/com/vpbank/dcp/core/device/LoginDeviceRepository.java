package com.vpbank.dcp.core.device;

import com.vpbank.dcp.core.customer.SubjectId;
import java.util.Optional;
import java.util.UUID;

/** Two reads: pre-password public key, then current owner-bound device facts. */
public interface LoginDeviceRepository {
    Optional<StoredDeviceKey> keyForProof(String publicBindingId);

    Optional<LoginDeviceSnapshot> current(SubjectId owner, String channel,
                                          String deviceId, String publicBindingId);

    Optional<LoginDeviceSnapshot> currentByBinding(SubjectId owner, String channel,
                                                   String deviceId, BindingId bindingId);
}
