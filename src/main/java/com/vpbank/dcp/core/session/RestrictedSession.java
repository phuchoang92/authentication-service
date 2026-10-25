package com.vpbank.dcp.core.session;

import java.util.Objects;
import java.util.UUID;

/**
 * What a NEED_TRUSTED_DEVICE login pins. It grants no banking access: only the trusted-device
 * API may use it, and every step re-checks the customer and device.
 *
 * <p>The App device ID is not part of it: it is passed to
 * {@link RestrictedSessionCryptography#prepare} once and only its digest is stored.
 */
public record RestrictedSession(UUID operationId, PinnedCustomer customer, PinnedDevice device,
                                LoginKeys keys, UUID generation) {
    public RestrictedSession {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(customer, "customer");
        Objects.requireNonNull(device, "device");
        Objects.requireNonNull(keys, "keys");
        Objects.requireNonNull(generation, "generation");
    }

    @Override
    public String toString() {
        return "RestrictedSession[redacted]";
    }
}
