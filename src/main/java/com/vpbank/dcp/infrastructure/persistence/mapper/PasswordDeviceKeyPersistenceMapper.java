package com.vpbank.dcp.infrastructure.persistence.mapper;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.infrastructure.persistence.projection.StoredDeviceKeyView;

/** Restores the pinned public key and its exact stored thumbprint. */
public final class PasswordDeviceKeyPersistenceMapper {
    private PasswordDeviceKeyPersistenceMapper() { }

    public static StoredDeviceKey toDomain(StoredDeviceKeyView view) {
        return new StoredDeviceKey(view.publicKeySpki(), Digest32.fromBytes(view.thumbprint()));
    }
}
