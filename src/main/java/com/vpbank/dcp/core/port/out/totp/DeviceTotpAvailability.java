package com.vpbank.dcp.core.port.out.totp;

import java.util.UUID;

/** Whether this already-owned trusted binding has a confirmed TOTP credential. */
public interface DeviceTotpAvailability {
    boolean hasActiveCredential(UUID bindingId);
}
