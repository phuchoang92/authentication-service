package com.vpbank.dcp.core.port.out.device;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
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
