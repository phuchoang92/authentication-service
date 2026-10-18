package com.vpbank.dcp.core.port.in.trusteddevice;

import java.util.Objects;

public sealed interface InitTrustedDeviceResult {

    record Started(String serverPublicJwk, String challengeJwe) implements InitTrustedDeviceResult {
        public Started {
            Objects.requireNonNull(serverPublicJwk);
            Objects.requireNonNull(challengeJwe);
        }
    }

    /** Wrong session, wrong step, wrong device or unusable key: start the login again. */
    record Rejected() implements InitTrustedDeviceResult { }

    record Unavailable() implements InitTrustedDeviceResult { }
}
