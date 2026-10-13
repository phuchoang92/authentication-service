package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.vpbank.dcp.core.port.out.totp.DeviceTotpAvailability;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpUnavailableException;
import com.vpbank.dcp.infrastructure.persistence.repository.DeviceCredentialJpaRepository;
import java.util.Objects;
import java.util.UUID;
import org.springframework.dao.DataAccessException;

public final class JpaDeviceTotpAvailability implements DeviceTotpAvailability {
    private final DeviceCredentialJpaRepository credentials;

    public JpaDeviceTotpAvailability(DeviceCredentialJpaRepository credentials) {
        this.credentials = Objects.requireNonNull(credentials);
    }

    @Override
    public boolean hasActiveCredential(UUID bindingId) {
        Objects.requireNonNull(bindingId);
        try {
            return credentials.countActive(bindingId) == 1;
        } catch (DataAccessException failure) {
            throw new DeviceTotpUnavailableException(failure);
        }
    }
}
