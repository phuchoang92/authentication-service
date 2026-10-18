package com.vpbank.dcp.core.port.in.trusteddevice;

import com.vpbank.dcp.core.port.out.session.PreparedSession;
import java.util.Objects;

public sealed interface ConfirmTrustedDeviceResult {

    /** Trusted and primary; a new ACTIVE session replaces the restricted one. */
    record Active(PreparedSession session) implements ConfirmTrustedDeviceResult {
        public Active {
            Objects.requireNonNull(session);
        }
    }

    /** MFA is not finished; the restricted session is kept so the App can confirm again. */
    record MfaPending() implements ConfirmTrustedDeviceResult { }

    record Expired() implements ConfirmTrustedDeviceResult { }

    record Rejected() implements ConfirmTrustedDeviceResult { }

    record Unavailable() implements ConfirmTrustedDeviceResult { }
}
