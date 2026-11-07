package com.vpbank.dcp.auth.domain.model;

import java.util.UUID;
import lombok.NonNull;

/** Primary key of a TRUSTED_DEVICE row (the binding), distinct from the app's DeviceId. */
public record TrustedDeviceId(@NonNull UUID value) {

    public static TrustedDeviceId random() {
        return new TrustedDeviceId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
