package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;
import java.util.UUID;

/** Primary key of a TRUSTED_DEVICE row (the binding), distinct from the app's DeviceId. */
public record TrustedDeviceId(UUID value) {
    public TrustedDeviceId {
        Objects.requireNonNull(value, "value");
    }

    public static TrustedDeviceId random() {
        return new TrustedDeviceId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
