package com.vpbank.dcp.core.port.in.trusteddevice;

import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.util.Objects;

/**
 * Who calls the trusted-device API, as asserted by the BFF after it authenticated the App token.
 * Every step checks all three against the restricted session.
 */
public record TrustedDeviceCaller(SessionTokenLookup session, String channel, String deviceId) {
    public TrustedDeviceCaller {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(deviceId, "deviceId");
    }

    @Override
    public String toString() {
        return "TrustedDeviceCaller[redacted]";
    }
}
