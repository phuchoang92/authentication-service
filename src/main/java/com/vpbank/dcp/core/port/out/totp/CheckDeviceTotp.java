package com.vpbank.dcp.core.port.out.totp;

import com.vpbank.dcp.core.domain.device.DeviceOwnership;
import com.vpbank.dcp.core.domain.totp.TotpCode;
import java.util.Objects;
import java.util.UUID;

/** The caller must have already admitted the server-owned login or MFA challenge. */
public record CheckDeviceTotp(DeviceOwnership owner, UUID bindingId, TotpCode code) {
    public CheckDeviceTotp {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(bindingId, "bindingId");
        Objects.requireNonNull(code, "code");
    }

    @Override
    public String toString() {
        return "CheckDeviceTotp[redacted]";
    }
}
