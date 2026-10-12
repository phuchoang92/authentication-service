package com.vpbank.dcp.core.port.out.password;

import java.util.Optional;

/** Pre-identity lookup is only key discovery; customer ownership is checked later. */
public interface PasswordDeviceKeyRepository {

    Optional<StoredDeviceKey> findActive(PasswordOperationContext operation);
}
