package com.vpbank.dcp.core.trusteddevice;

import com.vpbank.dcp.core.device.StoredDeviceKey;
import java.util.Objects;

/** The device public key the challenge is encrypted to. */
public sealed interface DeviceKeyMaterial {

    /** A known device keeps the key stored when it was trusted. */
    record Stored(StoredDeviceKey key) implements DeviceKeyMaterial {
        public Stored {
            Objects.requireNonNull(key, "key");
        }
    }

    /** A new device presents its public key at init; it is untrusted until confirm passes. */
    record Presented(String publicKey) implements DeviceKeyMaterial {
        public Presented {
            if (publicKey == null || publicKey.isBlank() || publicKey.length() > 4096) {
                throw new IllegalArgumentException("Invalid restricted session value");
            }
        }
    }
}
