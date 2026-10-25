package com.vpbank.dcp.core.trusteddevice;

import java.util.Objects;
import java.util.UUID;

public sealed interface InitTrustedDeviceResult {

    record Started(UUID enrollmentId, String suite, String serverPublicKey,
                   String protectedChallenge) implements InitTrustedDeviceResult {
        public Started {
            Objects.requireNonNull(enrollmentId);
            Objects.requireNonNull(suite);
            Objects.requireNonNull(serverPublicKey);
            Objects.requireNonNull(protectedChallenge);
        }
    }

    /** Wrong session, wrong step, wrong device or unusable key: start the login again. */
    record Rejected() implements InitTrustedDeviceResult { }

    record Unavailable() implements InitTrustedDeviceResult { }
}
