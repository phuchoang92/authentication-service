package com.vpbank.dcp.core.port.in.trusteddevice;

import java.util.Objects;
import java.util.UUID;

/**
 * Who calls the trusted-device API, as asserted by the BFF after it authenticated the App token.
 * Every step checks all three against the restricted session.
 */
public record TrustedDeviceCaller(UUID sessionId, String channel, String deviceId) {
    public TrustedDeviceCaller {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(deviceId, "deviceId");
    }

    @Override
    public String toString() {
        return "TrustedDeviceCaller[redacted]";
    }
}
