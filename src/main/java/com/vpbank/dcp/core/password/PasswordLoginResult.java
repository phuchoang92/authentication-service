package com.vpbank.dcp.core.password;

import com.vpbank.dcp.core.session.PreparedSession;
import java.time.Instant;
import java.util.Objects;

public sealed interface PasswordLoginResult {

    record Active(PreparedSession session) implements PasswordLoginResult { }

    /**
     * The password is correct but this device is not the trusted primary. The App receives a
     * restricted token usable only by the trusted-device API, which ends in a new session.
     */
    record NeedTrustedDevice(String tokenEnvelope, String receipt, Instant expiresAt)
            implements PasswordLoginResult {
        public NeedTrustedDevice {
            Objects.requireNonNull(tokenEnvelope);
            Objects.requireNonNull(receipt);
            Objects.requireNonNull(expiresAt);
        }

        @Override
        public String toString() {
            return "NeedTrustedDevice[redacted]";
        }
    }

    record Rejected() implements PasswordLoginResult { }

    record Conflict() implements PasswordLoginResult { }

    record TemporarilyUnavailable() implements PasswordLoginResult { }
}
