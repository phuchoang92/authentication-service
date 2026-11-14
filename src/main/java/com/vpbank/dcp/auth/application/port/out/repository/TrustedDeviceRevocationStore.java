package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.application.port.out.model.DeviceRevocation;

/** Atomic SQL transition of an exact binding. The online session guard has a separate contract. */
public interface TrustedDeviceRevocationStore {
    RevocationCommit revoke(DeviceRevocation command);

    enum RevocationCommit {
        COMMITTED,
        ALREADY_COMMITTED,
        NOT_FOUND,
        NOT_PRIMARY
    }
}
