package com.vpbank.dcp.core.port.out.trusteddevice;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.security.Digest32;
import java.util.Objects;

/** Which device the restricted session is trusting. Init handles the two cases differently. */
public sealed interface TrustTarget {

    /** No binding yet: the App sends its device public key at init. */
    record NewDevice() implements TrustTarget { }

    /**
     * A binding this customer owns and proved at login (trusted but not primary, or lapsed).
     * Its stored key is kept: the App generates the device key once.
     */
    record KnownDevice(BindingId bindingId, Digest32 deviceKeyThumbprint, long deviceSecurityVersion)
            implements TrustTarget {
        public KnownDevice {
            Objects.requireNonNull(bindingId, "bindingId");
            Objects.requireNonNull(deviceKeyThumbprint, "deviceKeyThumbprint");
            if (deviceSecurityVersion < 0) {
                throw new InvalidRestrictedSessionException();
            }
        }
    }
}
